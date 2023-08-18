package uk.gov.communities.delta.auth.controllers.internal

import io.ktor.server.application.*
import io.ktor.server.auth.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import kotlinx.serialization.Serializable
import org.slf4j.LoggerFactory
import uk.gov.communities.delta.auth.saml.SAMLTokenService
import uk.gov.communities.delta.auth.services.LdapUser
import uk.gov.communities.delta.auth.services.OAuthSession
import uk.gov.communities.delta.auth.services.UserLookupService

class RefreshUserInfoController(
    private val userLookupService: UserLookupService,
    private val samlTokenService: SAMLTokenService,
) {
    private val logger = LoggerFactory.getLogger(javaClass)

    fun route(route: Route) {
        route.get { getUserInfo(call) }
    }

    private suspend fun getUserInfo(call: ApplicationCall) {
        val session = call.principal<OAuthSession>()!!

        val user = userLookupService.lookupUserByCn(session.userCn)
        // The user's roles may have changed so generate a new token
        val samlToken = samlTokenService.samlTokenForSession(session, user)

        logger.info("Retrieved updated user info")
        call.respond(UserInfoResponse(user, samlToken.token, samlToken.expiry.epochSecond))
    }

    @Suppress("PropertyName")
    @Serializable
    data class UserInfoResponse(
        val delta_ldap_user: LdapUser,
        val saml_token: String,
        val expires_at_epoch_second: Long,
    )
}
