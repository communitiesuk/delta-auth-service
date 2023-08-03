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
import uk.gov.communities.delta.auth.config.AzureADSSOConfig
import uk.gov.communities.delta.auth.config.ClientConfig
import uk.gov.communities.delta.auth.config.DeltaConfig
import uk.gov.communities.delta.auth.security.SSOLoginStateService
import uk.gov.communities.delta.auth.services.IAuthorizationCodeService
import uk.gov.communities.delta.auth.services.UserLookupService
import uk.gov.communities.delta.auth.services.withAuthCode

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
        if (!call.parameters.contains("ssoClientId")) return call.response.status(HttpStatusCode.NotFound)
        if (call.parameters.contains("error")) {
            // This means Azure AD returned an error, probably because the user declined the login request
            return handleOAuthCallbackError(call)
        }

        // The OAuth authentication logic will fall through to here if the session is null or the state is invalid/expired
        val session = call.sessions.get<LoginSessionCookie>()
            ?: throw OAuthLoginException("Reached callback with no session")
        val stateValidationResult = ssoLoginStateService.validateCallSSOState(call)
        if (stateValidationResult != SSOLoginStateService.ValidateStateResult.VALID) {
            throw OAuthLoginException("OAuth callback state failed to validate ${stateValidationResult.name}")
        }

        val principal = call.principal<OAuthAccessTokenResponse.OAuth2>()
            ?: throw OAuthLoginException("No principal, the OAuth login fell through, but the checks above did not catch it")
        val email = extractEmailFromTrustedJwt(principal.accessToken)

        // TODO: Confirm email matches expected domain

        logger.info("OAuth callback successfully authenticated user with email {}, checking in on-prem AD", email)

        val user = try {
            ldapLookupService.lookupUserByCn(email.replace('@', '!'))
        } catch (e: Exception) {
            logger.error("Failed to lookup user in AD after OAuth login, email '{}'", email, e)
            // TODO: If the user doesn't exist should send them to the create account page with a message
            throw OAuthLoginException("User does not exist in Delta's AD")
        }

        // TODO: Check group membership with https://graph.microsoft.com/v1.0/me/checkMemberGroups
        // TODO: Check admin group membership similarly
        // TODO: Check user account control bits to ensure account is enabled

        if (!user.memberOfCNs.contains(deltaConfig.requiredGroupCn)) {
            logger.error("User '{}' is not member of required Delta group {}", user.cn, deltaConfig.requiredGroupCn)
            throw OAuthLoginException("User is not member of required Delta group")
        }

        val client = clientConfig.oauthClients.first { it.clientId == session.clientId }
        val authCode = authorizationCodeService.generateAndStore(
            userCn = user.cn, client = client, traceId = call.callId!!
        )

        logger.atInfo().withAuthCode(authCode).log("Successful OAuth login")
        call.respondRedirect(client.redirectUrl + "?code=${authCode.code}&state=${session.deltaState.encodeURLParameter()}")
    }

    private suspend fun ApplicationCall.redirectToDeltaLoginErrorPage(ssoError: String) {
        respondRedirect(
            deltaConfig.deltaWebsiteUrl + "/login?error=delta_sso_failed&sso_error=$ssoError&trace=${callId!!.encodeURLParameter()}"
        )
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

    class OAuthLoginException(message: String) : Exception(message)

    private suspend fun handleOAuthCallbackError(call: ApplicationCall) {
        val error = call.parameters["error"]!!
        val errorDescription = call.parameters["error_description"]
        logger.warn(
            "Logging in user with OAuth failed with error {}, description {}",
            keyValue("AzureOAuthError", error), errorDescription
        )
        call.redirectToDeltaLoginErrorPage(error.encodeURLParameter())
    }
}
