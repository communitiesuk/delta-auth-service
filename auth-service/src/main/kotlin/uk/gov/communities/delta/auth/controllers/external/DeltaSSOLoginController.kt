package uk.gov.communities.delta.auth.controllers.external

import io.ktor.http.*
import io.ktor.server.application.*
import io.ktor.server.auth.*
import io.ktor.server.plugins.callid.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import io.ktor.server.sessions.*
import io.ktor.util.*
import io.micrometer.core.instrument.Counter
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
import uk.gov.communities.delta.auth.plugins.HttpNotFound404PageException
import uk.gov.communities.delta.auth.plugins.UserVisibleServerError
import uk.gov.communities.delta.auth.repositories.LdapUser
import uk.gov.communities.delta.auth.services.*
import uk.gov.communities.delta.auth.services.sso.MicrosoftGraphService
import uk.gov.communities.delta.auth.services.sso.SSOLoginSessionStateService
import uk.gov.communities.delta.auth.utils.EmailAddressChecker
import uk.gov.communities.delta.auth.utils.emailToDomain

/*
 * Authenticating users via Azure AD
 */
class DeltaSSOLoginController(
    private val deltaConfig: DeltaConfig,
    private val clientConfig: ClientConfig,
    private val ssoConfig: AzureADSSOConfig,
    private val ssoLoginStateService: SSOLoginSessionStateService,
    private val ldapLookupService: UserLookupService,
    private val userGUIDMapService: UserGUIDMapService,
    private val authorizationCodeService: AuthorizationCodeService,
    private val microsoftGraphService: MicrosoftGraphService,
    private val registrationService: RegistrationService,
    private val organisationService: OrganisationService,
    private val ssoLoginCounter: Counter,
    private val userAuditService: UserAuditService,
) {
    private val logger = LoggerFactory.getLogger(javaClass)
    private val emailAddressChecker = EmailAddressChecker()

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
        logger.info("Callback request for client ${ssoClient.internalId}")

        if (call.parameters.contains("error")) {
            // This means Azure AD returned an error, probably because the user declined the login request
            return handleOAuthCallbackError(call)
        }

        // The OAuth authentication logic does check the session, but will fall through to here if it is null/invalid
        val session = validateOAuthStateInSession(call)

        val principal = call.principal<OAuthAccessTokenResponse.OAuth2>()!!
        val jwt = parseTrustedAzureJwt(principal.accessToken)
        val email = emailFromJwt(jwt, ssoClient)

        logger.info("OAuth callback successfully authenticated user with email {}, checking in on-prem AD", email)

        var userGUID = userGUIDMapService.userGUIDFromEmailIfExists(email)
        if (userGUID == null) {
            if (!ssoClient.required) {
                logger.info("User {} not found in AD, and SSO is not required, so redirecting to register page", email)
                return call.respondRedirect("/delta/register?fromSSOEmail=${email.encodeURLParameter()}")
            }
            val registration = Registration(jwt.givenName, jwt.familyName, email, jwt.userObjectId)
            logger.info(
                "SSO required user not found in AD, registering automatically using details from access token {}",
                registration,
            )
            val registrationResult = registrationService.register(
                registration,
                organisationService.findAllByDomain(emailToDomain(email)),
                call,
                ssoClient,
            )
            if (registrationResult !is RegistrationService.SSOUserCreated) {
                logger.error("Error creating SSO User, result was {}", registrationResult.toString())
                throw Exception("Error creating SSO User")
            }
            userGUID = userGUIDMapService.userGUIDFromEmailIfExists(email)!!
        }

        val user = ldapLookupService.lookupUserByGUID(userGUID)
        checkUserEnabled(user)
        checkUserHasEmail(user)
        lookupAndCheckAzureGroups(user, principal, ssoClient)
        checkDeltaUsersGroup(user)

        val client = clientConfig.oauthClients.first { it.clientId == session.clientId }
        val authCode = authorizationCodeService.generateAndStore(
            userGUID = user.getGUID(), client = client, traceId = call.callId!!, isSso = true
        )

        logger.atInfo().withAuthCode(authCode).log("Successful OAuth login")
        ssoLoginCounter.increment()
        userAuditService.userSSOLoginAudit(authCode.userGUID, ssoClient, jwt.userObjectId, call)
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
        if (!call.parameters.contains("ssoClientId")) throw HttpNotFound404PageException("No SSO Client id")
        val ssoClientId = call.parameters["ssoClientId"]!!
        return ssoConfig.ssoClients.firstOrNull { it.internalId == ssoClientId }
            ?: throw HttpNotFound404PageException("No OAuth client found for id $ssoClientId")
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

    private fun checkUserEnabled(user: LdapUser) {
        if (!user.accountEnabled) {
            throw OAuthLoginException(
                "user_disabled",
                "User ${user.getGUID()} is disabled in Active Directory, login blocked",
                "Your Delta user account is disabled. If you haven't used your account before please check for an activation email otherwise please contact the service desk"
            )
        }
    }

    private fun checkUserHasEmail(user: LdapUser) {
        if (user.email.isNullOrEmpty()) {
            throw OAuthLoginException(
                "user_no_mail_attribute",
                "User ${user.getGUID()} has no email set in Active Directory, login blocked",
                "Your Delta user account is not fully set up (missing mail attribute). Please contact the Service Desk."
            )
        }
    }

    private fun emailFromJwt(jwt: JwtBody, ssoClient: AzureADSSOClient): String {
        val email = jwt.uniqueName.lowercase()
        if (!emailAddressChecker.hasValidFormat(email)) {
            logger.error("SSO user has invalid email '{}'", email)
            throw OAuthLoginException(
                "invalid_email_address",
                "Invalid email address '$email'",
                "Single Sign On is misconfigured for your user (invalid email address). Please contact the service desk"
            )
        }
        return when {
            email.endsWith(ssoClient.emailDomain) -> email
            ssoClient.convertFromEmailDomain != null && email.endsWith(ssoClient.convertFromEmailDomain) -> {
                email.replace(ssoClient.convertFromEmailDomain, ssoClient.emailDomain)
            }

            else ->
                throw OAuthLoginException(
                    "invalid_email_domain",
                    "Expected email for SSO client ${ssoClient.internalId} to end with ${ssoClient.emailDomain}, but was '$email'",
                    "Single Sign On is misconfigured for your user (unexpected email domain). Please contact the service desk"
                )
        }
    }

    private suspend fun lookupAndCheckAzureGroups(
        user: LdapUser,
        principal: OAuthAccessTokenResponse.OAuth2,
        ssoClient: AzureADSSOClient,
    ) {
        val groups = listOfNotNull(ssoClient.requiredGroupId, ssoClient.requiredAdminGroupId)
        if (groups.isEmpty()) return
        val azGroups = microsoftGraphService.checkCurrentUserGroups(principal.accessToken, groups)

        if (ssoClient.requiredGroupId != null && !azGroups.contains(ssoClient.requiredGroupId)) {
            throw OAuthLoginException(
                "not_in_required_azure_group",
                "User ${user.getGUID()} not in required Azure group ${ssoClient.requiredGroupId}",
                "This account (${user.cn.replace('!', '@')}) is not configured for Single Sign On for Delta (not in required Azure AD users group ${ssoClient.requiredGroupId}). Please contact the Service Desk"
            )
        }

        val adminGroups = user.memberOfCNs.filter { AzureADSSOConfig.DELTA_ADMIN_ROLES.contains(it) }
        if (adminGroups.isNotEmpty() && ssoClient.requiredAdminGroupId != null && !azGroups.contains(ssoClient.requiredAdminGroupId)) {
            throw OAuthLoginException(
                "not_in_required_admin_group",
                "User ${user.getGUID()} is admin in Delta (member of ${adminGroups.joinToString(", ")}), but not member of required admin group ${ssoClient.requiredAdminGroupId}",
                "You are an admin user in Delta, but have not been added to the Delta Admin SSO Users group in ${ssoClient.internalId.uppercase()} (${ssoClient.requiredAdminGroupId}). Please contact the Service Desk"
            )
        }
    }

    private fun checkDeltaUsersGroup(user: LdapUser) {
        if (!user.memberOfCNs.contains(DeltaConfig.DATAMART_DELTA_USER)) {
            logger.error(
                "User {} is not a member of required Delta group {}",
                keyValue("userGUID", user.getGUID()),
                DeltaConfig.DATAMART_DELTA_USER
            )
            throw OAuthLoginException(
                "not_delta_user",
                "User ${user.getGUID()} is not member of required Delta group ${DeltaConfig.DATAMART_DELTA_USER}",
                "Your Delta user is misconfigured (not in ${DeltaConfig.DATAMART_DELTA_USER}). Please contact the Service Desk",
            )
        }
    }

    @Serializable
    // Azure AD doesn't seem to validate emails at all so using the "email" claim doesn't seem ideal
    data class JwtBody(
        @SerialName("unique_name") val uniqueName: String,
        @SerialName("given_name") val givenName: String,
        @SerialName("family_name") val familyName: String,
        @SerialName("oid") val userObjectId: String,
    )

    private val jsonIgnoreUnknown = Json { ignoreUnknownKeys = true }

    private fun parseTrustedAzureJwt(jwt: String): JwtBody {
        try {
            val split = jwt.split('.')
            if (split.size != 3) throw InvalidJwtException("Invalid JWT, expected 3 components got ${split.size}}")
            val jsonString = split[1].decodeBase64String()
            logger.debug("JWT Body {}", jsonString)
            return jsonIgnoreUnknown.decodeFromString<JwtBody>(jsonString)
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
