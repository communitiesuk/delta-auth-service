package uk.gov.communities.delta.auth.services.sso

import io.ktor.server.application.*
import io.ktor.server.sessions.*
import io.ktor.util.*
import org.slf4j.LoggerFactory
import uk.gov.communities.delta.auth.LoginSessionCookie
import uk.gov.communities.delta.auth.config.AzureADSSOClient
import kotlin.time.Duration.Companion.minutes

/*
 * Service for checking the state parameter when acting as an OAuth client.
 *
 * When redirecting to Microsoft login we send a "state" query parameter with a random value in and
 * store the same value in a cookie.
 * Microsoft sends the "state" parameter back in the callback, and we check it matches the cookie.
 * See <https://www.rfc-editor.org/rfc/rfc6749#section-10.12>
 */
class SSOLoginSessionStateService {
    private val logger = LoggerFactory.getLogger(javaClass)
    private val validateStateAttributeKey = AttributeKey<ValidateStateResult>("DELTA_OAUTH_VALIDATE_STATE")
    private val ssoStateTimeoutMillis = 10.minutes.inWholeMilliseconds

    fun onSSOStateCreated(call: ApplicationCall, state: String, ssoClient: AzureADSSOClient) {
        logger.info("Updating session with state {} for client {}", state, ssoClient)
        val session = call.sessions.get<LoginSessionCookie>()!!
        call.sessions.set(
            session.copy(
                ssoState = state,
                ssoAt = System.currentTimeMillis(),
                ssoClient = ssoClient.internalId
            )
        )
    }

    fun validateCallSSOState(call: ApplicationCall): ValidateStateResult {
        // We cache the result in a call attribute since we clear the session after checking it
        val fromCall = call.attributes.getOrNull(validateStateAttributeKey)
        if (fromCall != null) return fromCall

        val result = validateState(call)
        call.attributes.put(validateStateAttributeKey, result)
        return result
    }

    private fun validateState(call: ApplicationCall): ValidateStateResult {
        val state = call.parameters["state"] ?: return ValidateStateResult.NO_STATE
        val ssoClientId = call.parameters["ssoClientId"] ?: return ValidateStateResult.NO_SSO_CLIENT
        val session = call.sessions.get<LoginSessionCookie>() ?: return ValidateStateResult.NO_SESSION
        if (session.ssoState == null || session.ssoAt == null || session.ssoClient == null) return ValidateStateResult.SESSION_NO_OAUTH
        logger.debug("Clearing SSO state from session cookie")
        call.sessions.set(session.copy(ssoState = null, ssoAt = null, ssoClient = null))

        if (session.ssoClient != ssoClientId) return ValidateStateResult.SSO_CLIENT_MISMATCH
        if (session.ssoState != state) return ValidateStateResult.STATE_MISMATCH
        if ((session.ssoAt + ssoStateTimeoutMillis) < System.currentTimeMillis()) return ValidateStateResult.EXPIRED
        return ValidateStateResult.VALID
    }

    enum class ValidateStateResult {
        NO_STATE, NO_SSO_CLIENT, NO_SESSION, SESSION_NO_OAUTH, SSO_CLIENT_MISMATCH, STATE_MISMATCH, EXPIRED, VALID;
    }
}
