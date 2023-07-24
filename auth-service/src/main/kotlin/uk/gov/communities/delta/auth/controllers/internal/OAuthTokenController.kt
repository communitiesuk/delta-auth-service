package uk.gov.communities.delta.auth.controllers.internal

import io.ktor.http.*
import io.ktor.server.application.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.ktor.server.util.*
import kotlinx.serialization.Serializable
import org.slf4j.LoggerFactory
import uk.gov.communities.delta.auth.config.ClientConfig
import uk.gov.communities.delta.auth.saml.SAMLTokenService
import uk.gov.communities.delta.auth.services.*
import java.nio.charset.StandardCharsets
import java.security.MessageDigest

class OAuthTokenController(
    private val clientConfig: ClientConfig,
    private val authorizationCodeService: IAuthorizationCodeService,
    private val userLookupService: UserLookupService,
    private val samlTokenService: SAMLTokenService,
    private val oAuthSessionService: OAuthSessionService,
) {
    private val logger = LoggerFactory.getLogger(javaClass)
    companion object {
        private const val TOKEN_EXPIRY_SECONDS = 43200L
    }

    suspend fun getToken(call: ApplicationCall) {
        val params = call.receiveParameters()
        val code = params.getOrFail("code")
        val clientId = params.getOrFail("client_id")
        val clientSecret = params.getOrFail("client_secret")

        if (clientId != clientConfig.deltaWebsite.clientId) {
            logger.error("Client id mismatch {}", clientId)
            return call.respond(
                HttpStatusCode.BadRequest,
                JsonErrorResponse("invalid_client", "Invalid client id or secret")
            )
        }
        if (!compareClientSecret(clientSecret, clientConfig.deltaWebsite.clientSecret)) {
            logger.error("Invalid client secret for client {}", clientId)
            return call.respond(
                HttpStatusCode.BadRequest,
                JsonErrorResponse("invalid_client", "Invalid client id or secret")
            )
        }

        val authCode = authorizationCodeService.lookupAndInvalidate(code)
        if (authCode == null) {
            logger.error("Invalid auth code {}", code)
            return call.respond(HttpStatusCode.BadRequest, JsonErrorResponse("invalid_grant", "Invalid auth code"))
        }
        val session = oAuthSessionService.create(authCode)
        val user = userLookupService.lookupUserByCn(session.userCn)
        val samlToken = samlToken(session, user)

        logger.atInfo().withSession(session).log("Successful token request")

        call.respond(
            AccessTokenResponse(
                access_token = session.authToken,
                delta_ldap_user = user,
                saml_token = samlToken,
            )
        )
    }

    @Suppress("PropertyName")
    @Serializable
    data class AccessTokenResponse(
        val access_token: String,
        val delta_ldap_user: LdapUser,
        val saml_token: String,
        // TODO remove
        val delta_user: String = delta_ldap_user.cn,
        val token_type: String = "bearer",
        val expires_in: String = TOKEN_EXPIRY_SECONDS.toString(),
    )

    private fun compareClientSecret(req: String, correct: String): Boolean {
        val requestClientSecretBytes = req.toByteArray(StandardCharsets.UTF_8)
        val correctSecretBytes = correct.toByteArray(StandardCharsets.UTF_8)
        return MessageDigest.isEqual(requestClientSecretBytes, correctSecretBytes)
    }

    private fun samlToken(session: OAuthSession, user: LdapUser): String {
        val expiry = session.createdAt.plusSeconds(TOKEN_EXPIRY_SECONDS)
        return samlTokenService.generate(user, session.createdAt, expiry)
    }
}
