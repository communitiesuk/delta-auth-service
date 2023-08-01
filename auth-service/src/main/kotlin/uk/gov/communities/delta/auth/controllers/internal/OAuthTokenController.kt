package uk.gov.communities.delta.auth.controllers.internal

import io.ktor.http.*
import io.ktor.server.application.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import io.ktor.server.util.*
import kotlinx.serialization.Serializable
import org.slf4j.LoggerFactory
import uk.gov.communities.delta.auth.config.OAuthClient
import uk.gov.communities.delta.auth.saml.SAMLTokenService
import uk.gov.communities.delta.auth.security.ClientSecretCheck
import uk.gov.communities.delta.auth.services.*
import java.time.Instant

class OAuthTokenController(
    private val clients: List<OAuthClient>,
    private val authorizationCodeService: IAuthorizationCodeService,
    private val userLookupService: UserLookupService,
    private val samlTokenService: SAMLTokenService,
    private val oAuthSessionService: OAuthSessionService,
) {
    private val logger = LoggerFactory.getLogger(javaClass)

    companion object {
        const val TOKEN_EXPIRY_SECONDS = 43200L
    }

    fun route(route: Route) {
        route.post { getToken(call) }
    }

    private suspend fun getToken(call: ApplicationCall) {
        val params = call.receiveParameters()
        val code = params.getOrFail("code")
        val clientId = params.getOrFail("client_id")
        val clientSecret = params.getOrFail("client_secret")

        val client = ClientSecretCheck.getClient(clients, clientId, clientSecret)
            ?: return call.respond(
                HttpStatusCode.BadRequest,
                JsonErrorResponse("invalid_client", "Invalid client id or secret")
            )

        val authCode = authorizationCodeService.lookupAndInvalidate(code, client)
        if (authCode == null) {
            logger.error("Invalid auth code {}", code)
            return call.respond(HttpStatusCode.BadRequest, JsonErrorResponse("invalid_grant", "Invalid auth code"))
        }
        val session = oAuthSessionService.create(authCode, client)
        val user = userLookupService.lookupUserByCn(session.userCn)
        val samlToken = samlTokenService.samlTokenForSession(session, user)

        logger.atInfo().withSession(session).log("Successful token request")

        call.respond(
            AccessTokenResponse(
                access_token = session.authToken,
                delta_ldap_user = user,
                saml_token = samlToken.token,
                expires_at_epoch_second = samlToken.expiry.epochSecond
            )
        )
    }

    @Suppress("PropertyName")
    @Serializable
    data class AccessTokenResponse(
        val access_token: String,
        val delta_ldap_user: LdapUser,
        val saml_token: String,
        val expires_at_epoch_second: Long,
        // TODO remove delta_user property
        val delta_user: String = delta_ldap_user.cn,
        val token_type: String = "bearer",
        val expires_in: String = TOKEN_EXPIRY_SECONDS.toString(),
    )
}

data class SamlTokenWithExpiry(val token: String, val expiry: Instant)

fun SAMLTokenService.samlTokenForSession(session: OAuthSession, user: LdapUser): SamlTokenWithExpiry {
    val expiry = session.createdAt.plusSeconds(OAuthTokenController.TOKEN_EXPIRY_SECONDS)
    return SamlTokenWithExpiry(generate(session.client.samlCredential, user, session.createdAt, expiry), expiry)
}
