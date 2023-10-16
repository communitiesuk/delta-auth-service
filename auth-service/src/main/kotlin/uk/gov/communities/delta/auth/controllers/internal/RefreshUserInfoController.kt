package uk.gov.communities.delta.auth.controllers.internal

import io.ktor.server.application.*
import io.ktor.server.auth.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.serialization.Serializable
import org.slf4j.LoggerFactory
import uk.gov.communities.delta.auth.saml.SAMLTokenService
import uk.gov.communities.delta.auth.services.*

class RefreshUserInfoController(
    private val userLookupService: UserLookupService,
    private val samlTokenService: SAMLTokenService,
    private val accessGroupsService: AccessGroupsService,
    private val organisationService: OrganisationService,
    private val memberOfToDeltaRolesMapperFactory: MemberOfToDeltaRolesMapperFactory,
) {
    private val logger = LoggerFactory.getLogger(javaClass)

    fun route(route: Route) {
        route.get { getUserInfo(call) }
    }

    private suspend fun getUserInfo(call: ApplicationCall) {
        val session = call.principal<OAuthSession>()!!

        val user = userLookupService.lookupUserByCn(session.userCn)

        coroutineScope {
            val allOrganisations = async { organisationService.findAllNamesAndCodes() }
            val allAccessGroups = async { accessGroupsService.getAllAccessGroups() }

            val samlToken = samlTokenService.samlTokenForSession(session, user)

            val roles = memberOfToDeltaRolesMapperFactory(
                user.cn, allOrganisations.await(), allAccessGroups.await()
            ).map(user.memberOfCNs)

            logger.info("Retrieved updated user info")
            call.respond(UserInfoResponse(user, samlToken.token, roles, samlToken.expiry.epochSecond))
        }
    }

    @Suppress("PropertyName")
    @Serializable
    data class UserInfoResponse(
        val delta_ldap_user: LdapUser,
        val saml_token: String,
        val delta_user_roles: MemberOfToDeltaRolesMapper.Roles,
        val expires_at_epoch_second: Long,
    )
}
