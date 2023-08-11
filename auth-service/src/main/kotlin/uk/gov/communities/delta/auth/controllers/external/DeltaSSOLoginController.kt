package uk.gov.communities.delta.auth.controllers.external

import io.ktor.http.*
import io.ktor.server.application.*
import io.ktor.server.auth.*
import io.ktor.server.plugins.callid.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import io.ktor.server.sessions.*
import io.ktor.util.*
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import net.logstash.logback.argument.StructuredArguments.keyValue
import org.slf4j.LoggerFactory
import uk.gov.communities.delta.auth.LoginSessionCookie
import uk.gov.communities.delta.auth.config.AzureADSSOClient
import uk.gov.communities.delta.auth.config.AzureADSSOConfig
import uk.gov.communities.delta.auth.config.ClientConfig
import uk.gov.communities.delta.auth.config.DeltaConfig
import uk.gov.communities.delta.auth.plugins.HttpNotFoundException
import uk.gov.communities.delta.auth.plugins.UserVisibleServerError
import uk.gov.communities.delta.auth.services.IAuthorizationCodeService
import uk.gov.communities.delta.auth.services.LdapUser
import uk.gov.communities.delta.auth.services.UserLookupService
import uk.gov.communities.delta.auth.services.sso.MicrosoftGraphService
import uk.gov.communities.delta.auth.services.sso.SSOLoginSessionStateService
import uk.gov.communities.delta.auth.services.withAuthCode
import javax.naming.NameNotFoundException

/*
 * Authenticating users via Azure AD
 */
class DeltaSSOLoginController(
    private val deltaConfig: DeltaConfig,
    private val clientConfig: ClientConfig,
    private val ssoConfig: AzureADSSOConfig,
    private val ssoLoginStateService: SSOLoginSessionStateService,
    private val ldapLookupService: UserLookupService,
    private val authorizationCodeService: IAuthorizationCodeService,
    private val microsoftGraphService: MicrosoftGraphService,
) {
    private val logger = LoggerFactory.getLogger(javaClass)

    fun route(route: Route) {
        route.get("/login") {
            val ssoClient = getSSOClient(call)
            throw OAuthLoginException(
                "reached_login_page",
                "Reached the OAuth login page for client ${ssoClient.internalId}, this isn't supposed to happen, it only exists to trigger the redirect"
            )
        }
        route.get("/callback") {
            callback(call)
        }
    }

    private suspend fun callback(call: ApplicationCall) {
        val ssoClient = getSSOClient(call)

        if (call.parameters.contains("error")) {
            // This means Azure AD returned an error, probably because the user declined the login request
            return handleOAuthCallbackError(call)
        }

        // The OAuth authentication logic does check the session, but will fall through to here if it is null/invalid
        val session = validateOAuthStateInSession(call)

        val principal = call.principal<OAuthAccessTokenResponse.OAuth2>()!!
        val email = extractEmailFromTrustedJwt(principal.accessToken)
        checkEmailDomain(email, ssoClient)

        logger.info("OAuth callback successfully authenticated user with email {}, checking in on-prem AD", email)

        val user = lookupUserInAd(email)
            ?: return call.respondRedirect(deltaConfig.deltaWebsiteUrl + "/register?from_sso_client=${ssoClient.internalId}&email=${email.encodeURLParameter()}")

        checkUserEnabled(user)
        lookupAndCheckAzureGroups(user, principal, ssoClient)
        checkDeltaUsersGroup(user)

        val client = clientConfig.oauthClients.first { it.clientId == session.clientId }
        val authCode = authorizationCodeService.generateAndStore(
            userCn = user.cn, client = client, traceId = call.callId!!
        )

        logger.atInfo().withAuthCode(authCode).log("Successful OAuth login")
        call.sessions.clear<LoginSessionCookie>()
        call.respondRedirect(client.deltaWebsiteUrl + "/login/oauth2/redirect?code=${authCode.code}&state=${session.deltaState.encodeURLParameter()}")
    }

    private suspend fun ApplicationCall.redirectToDeltaLoginErrorPage(ssoError: String) {
        respondRedirect(
            deltaConfig.deltaWebsiteUrl + "/login?error=delta_sso_failed&sso_error=$ssoError&trace=${callId!!.encodeURLParameter()}"
        )
    }

    private suspend fun handleOAuthCallbackError(call: ApplicationCall) {
        val error = call.parameters["error"]!!
        val errorDescription = call.parameters["error_description"]
        logger.warn(
            "Logging in user with OAuth failed with error {}, description {}",
            keyValue("AzureOAuthError", error), errorDescription
        )
        call.redirectToDeltaLoginErrorPage(error.encodeURLParameter())
    }

    private fun getSSOClient(call: ApplicationCall): AzureADSSOClient {
        if (!call.parameters.contains("ssoClientId")) throw HttpNotFoundException("No SSO Client id")
        val ssoClientId = call.parameters["ssoClientId"]!!
        return ssoConfig.ssoClients.firstOrNull { it.internalId == ssoClientId }
            ?: throw HttpNotFoundException("No OAuth client found for id $ssoClientId")
    }

    private fun validateOAuthStateInSession(call: ApplicationCall): LoginSessionCookie {
        val session = call.sessions.get<LoginSessionCookie>()
            ?: throw OAuthLoginException("callback_no_session", "Reached callback with no session")
        val stateValidationResult = ssoLoginStateService.validateCallSSOState(call)
        if (stateValidationResult != SSOLoginSessionStateService.ValidateStateResult.VALID) {
            throw OAuthLoginException(
                "callback_invalid_state",
                "OAuth callback state failed to validate ${stateValidationResult.name}"
            )
        }
        return session
    }

    private fun lookupUserInAd(email: String): LdapUser? {
        val cn = email.replace('@', '!')
        return try {
            ldapLookupService.lookupUserByCn(cn)
        } catch (e: NameNotFoundException) {
            logger.info("User not found in Active Directory {}", keyValue("username", cn), e)
            null
        } catch (e: Exception) {
            logger.error("Failed to lookup user in AD after OAuth login {}", keyValue("username", cn), e)
            throw e
        }
    }

    private fun checkUserEnabled(user: LdapUser) {
        if (!user.accountEnabled) {
            throw OAuthLoginException(
                "user_disabled",
                "User ${user.cn} is disabled in Active Directory, login blocked",
                "Your Delta user account is disabled. Please contact the service desk"
            )
        }
    }

    private fun checkEmailDomain(email: String, ssoClient: AzureADSSOClient) {
        if (ssoClient.emailDomain != null && !email.endsWith(ssoClient.emailDomain)) {
            throw OAuthLoginException(
                "invalid_email_domain",
                "Expected email for SSO client ${ssoClient.internalId} to end with ${ssoClient.emailDomain}, but was $email",
                "Single Sign On is misconfigured for your user (unexpected email domain). Please contact the service desk"
            )
        }
    }

    private suspend fun lookupAndCheckAzureGroups(
        user: LdapUser,
        principal: OAuthAccessTokenResponse.OAuth2,
        ssoClient: AzureADSSOClient
    ) {
        val groups = listOfNotNull(ssoClient.requiredGroupId, ssoClient.requiredAdminGroupId)
        if (groups.isEmpty()) return
        val azGroups = microsoftGraphService.checkCurrentUserGroups(principal.accessToken, groups)

        if (ssoClient.requiredGroupId != null && !azGroups.contains(ssoClient.requiredGroupId)) {
            throw OAuthLoginException(
                "not_in_required_azure_group",
                "User ${user.cn} not in required Azure group ${ssoClient.requiredGroupId}",
                // TODO DT-572 Process for adding users to group in DLUHC Azure AD
                "To use Single Sign On you must be added to the Delta SSO Users group in ${ssoClient.internalId.uppercase()} before you can use this service. Please contact the Service Desk"
            )
        }

        val adminGroups = user.memberOfCNs.filter { AzureADSSOConfig.DELTA_ADMIN_ROLES.contains(it) }
        if (adminGroups.isNotEmpty() && ssoClient.requiredAdminGroupId != null && !azGroups.contains(ssoClient.requiredAdminGroupId)) {
            throw OAuthLoginException(
                "not_in_required_admin_group",
                "User ${user.cn} is admin in Delta (member of ${adminGroups.joinToString(", ")}, but not member of required admin group ${ssoClient.requiredAdminGroupId}",
                // TODO DT-572 Process for adding users to group in DLUHC Azure AD
                "You are an admin user in Delta, but have not been added to the Delta Admin SSO Users group in ${ssoClient.internalId.uppercase()}. Please contact the Service Desk"
            )
        }
    }

    private fun checkDeltaUsersGroup(user: LdapUser) {
        if (!user.memberOfCNs.contains(deltaConfig.requiredGroupCn)) {
            logger.error(
                "User {} is not a member of required Delta group {}",
                keyValue("username", user.cn),
                deltaConfig.requiredGroupCn
            )
            throw OAuthLoginException(
                "not_delta_user",
                "User ${user.cn} is not member of required Delta group ${deltaConfig.requiredGroupCn}",
                "Your Delta user is misconfigured (not in ${deltaConfig.requiredGroupCn}). Please contact the Service Desk",
            )
        }
    }

    @Serializable
    // TODO DT-572 Figure out whether unique_name is reliably the user's email address in DLUHC AD
    // Azure AD doesn't seem to validate emails at all so using the "email" claim doesn't seem ideal
    data class JwtBody(@SerialName("unique_name") val uniqueName: String)

    private val jsonIgnoreUnknown = Json { ignoreUnknownKeys = true }

    private fun extractEmailFromTrustedJwt(jwt: String): String {
        try {
            val split = jwt.split('.')
            if (split.size != 3) throw InvalidJwtException("Invalid JWT, expected 3 components got ${split.size}}")
            val jsonString = split[1].decodeBase64String()
            return jsonIgnoreUnknown.decodeFromString<JwtBody>(jsonString).uniqueName
        } catch (e: Exception) {
            logger.error("Error parsing JWT '{}'", jwt)
            throw InvalidJwtException("Error parsing JWT", e)
        }
    }

    class InvalidJwtException(message: String, cause: Exception? = null) : Exception(message, cause)

    class OAuthLoginException(
        errorCode: String,
        exceptionMessage: String,
        userVisibleMessage: String = "Something went wrong logging you in, please try again",
    ) : UserVisibleServerError(errorCode, exceptionMessage, userVisibleMessage, "Login Error")
}
