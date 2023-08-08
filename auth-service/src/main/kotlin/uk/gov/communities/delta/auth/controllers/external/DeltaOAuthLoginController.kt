package uk.gov.communities.delta.auth.controllers.external

import io.ktor.http.*
import io.ktor.server.application.*
import io.ktor.server.auth.*
import io.ktor.server.plugins.callid.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import io.ktor.server.sessions.*
import io.ktor.util.*
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
import uk.gov.communities.delta.auth.security.SSOLoginStateService
import uk.gov.communities.delta.auth.services.*

/**
 * Authenticating users via Azure AD
 */
class DeltaOAuthLoginController(
    private val deltaConfig: DeltaConfig,
    private val clientConfig: ClientConfig,
    private val ssoConfig: AzureADSSOConfig,
    private val ssoLoginStateService: SSOLoginStateService,
    private val ldapLookupService: UserLookupService,
    private val authorizationCodeService: IAuthorizationCodeService,
    private val microsoftGraphService: MicrosoftGraphService,
) {
    private val logger = LoggerFactory.getLogger(javaClass)

    fun route(route: Route) {
        route.get("/login") {
            logger.warn(
                "Reached the OAuth login page for client {}, this isn't supposed to happen, it only exists to trigger the redirect",
                call.parameters["ssoClientId"]
            )
            call.response.status(HttpStatusCode.NotFound)
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

        lookupAndCheckAzureGroups(user, principal, ssoClient)
        checkDeltaUsersGroup(user)

        // TODO: Check user account control bits to ensure account is enabled

        val client = clientConfig.oauthClients.first { it.clientId == session.clientId }
        val authCode = authorizationCodeService.generateAndStore(
            userCn = user.cn, client = client, traceId = call.callId!!
        )

        logger.atInfo().withAuthCode(authCode).log("Successful OAuth login")
        call.sessions.clear<LoginSessionCookie>()
        call.respondRedirect(client.redirectUrl + "?code=${authCode.code}&state=${session.deltaState.encodeURLParameter()}")
    }

    private suspend fun ApplicationCall.redirectToDeltaLoginErrorPage(ssoError: String) {
        respondRedirect(
            deltaConfig.deltaWebsiteUrl + "/login?error=delta_sso_failed&sso_error=$ssoError&trace=${callId!!.encodeURLParameter()}"
        )
    }

    class OAuthLoginException(
        exceptionMessage: String,
        userVisibleMessage: String = "Something went wrong logging you in, please try again"
    ) :
        UserVisibleServerError(exceptionMessage, userVisibleMessage, "Login Error")

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
        return ssoConfig.ssoClients.firstOrNull { it.internalClientId == ssoClientId }
            ?: throw HttpNotFoundException("Callback no OAuth client found for id $ssoClientId")
    }

    private fun validateOAuthStateInSession(call: ApplicationCall): LoginSessionCookie {
        val session = call.sessions.get<LoginSessionCookie>()
            ?: throw OAuthLoginException("Reached callback with no session")
        val stateValidationResult = ssoLoginStateService.validateCallSSOState(call)
        if (stateValidationResult != SSOLoginStateService.ValidateStateResult.VALID) {
            throw OAuthLoginException("OAuth callback state failed to validate ${stateValidationResult.name}")
        }
        return session
    }

    private fun lookupUserInAd(email: String): LdapUser {
        try {
            return ldapLookupService.lookupUserByCn(email.replace('@', '!'))
        } catch (e: Exception) {
            logger.error("Failed to lookup user in AD after OAuth login, email '{}'", email, e)
            // TODO: If the user doesn't exist should send them to the create account page with a message
            throw OAuthLoginException("Failed to look up user")
        }
    }

    private fun checkEmailDomain(email: String, ssoClient: AzureADSSOClient) {
        if (ssoClient.emailDomain != null && !email.endsWith(ssoClient.emailDomain)) {
            throw OAuthLoginException(
                "Expected email for sso client ${ssoClient.internalClientId} to end with ${ssoClient.emailDomain}, but was $email",
                "Single Sign On is misconfigured for your user (unexpected email domain). Please contact the service desk."
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
                "User ${user.cn} not in required Azure group ${ssoClient.requiredGroupId}",
                // TODO: Process for adding users to group
                "You must be added to the Delta Users group in ${ssoClient.internalClientId.uppercase()} before you can use this service. Please contact qq@levellingup.gov.uk"
            )
        }

        val adminGroups = user.memberOfCNs.filter { AzureADSSOConfig.DELTA_ADMIN_ROLES.contains(it) }
        if (adminGroups.isNotEmpty() && ssoClient.requiredAdminGroupId != null && !azGroups.contains(ssoClient.requiredAdminGroupId)) {
            throw OAuthLoginException(
                "User ${user.cn} is admin in Delta (member of ${adminGroups.joinToString(", ")}, but not member of required admin group ${ssoClient.requiredAdminGroupId}",
                // TODO: Process for adding users to group
                "You are an admin user in Delta, but have not been added to the Delta Admin Users group in ${ssoClient.internalClientId.uppercase()}. Please contact qq@levellingup.gov.uk"
            )
        }
    }

    private fun checkDeltaUsersGroup(user: LdapUser) {
        if (!user.memberOfCNs.contains(deltaConfig.requiredGroupCn)) {
            logger.error("User '{}' is not member of required Delta group {}", user.cn, deltaConfig.requiredGroupCn)
            throw OAuthLoginException(
                "User is not member of required Delta group",
                "Your Delta user is misconfigured (not in ${deltaConfig.requiredGroupCn}). Please contact the Service Desk.",
            )
        }
    }

    @Serializable
    // TODO: Figure out if we reliably get this claim in the JWT, and if it's the best one to use
    data class JwtBody(val email: String)

    private val jsonIgnoreUnknown = Json { ignoreUnknownKeys = true }

    private fun extractEmailFromTrustedJwt(jwt: String): String {
        try {
            val split = jwt.split('.')
            if (split.size != 3) throw InvalidJwtException("Invalid JWT, expected 3 components got ${split.size}}")
            val jsonString = split[1].decodeBase64String()
            return jsonIgnoreUnknown.decodeFromString<JwtBody>(jsonString).email
        } catch (e: Exception) {
            logger.error("Error parsing JWT '{}'", jwt)
            throw InvalidJwtException("Error parsing JWT", e)
        }
    }

    class InvalidJwtException(message: String, cause: Exception? = null) : Exception(message, cause)
}
