package uk.gov.communities.delta.auth.controllers.internal

import com.google.common.base.Strings
import io.ktor.server.application.*
import io.ktor.server.auth.*
import io.ktor.server.response.*
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.serialization.Serializable
import org.slf4j.LoggerFactory
import uk.gov.communities.delta.auth.repositories.LdapUser
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

    private suspend fun getUserInfo(call: ApplicationCall, user: LdapUser): UserInfoResponse{
        val session = call.principal<OAuthSession>()!!
        return coroutineScope {
            val allOrganisations = async { organisationService.findAllNamesAndCodes() }
            val allAccessGroups = async { accessGroupsService.getAllAccessGroups() }

            val samlToken = samlTokenService.samlTokenForSession(session, user)

            val roles = memberOfToDeltaRolesMapperFactory(
                user.cn, allOrganisations.await(), allAccessGroups.await()
            ).map(user.memberOfCNs)

            logger.info("Retrieved updated user info")
            call.respond(UserInfoResponse(user, samlToken.token, roles, samlToken.expiry.epochSecond, session.isSso))
        }
    }

    suspend fun refreshUserInfo(call: ApplicationCall) {
        val session = call.principal<OAuthSession>()!!
        val user = userLookupService.lookupUserByCn(session.userCn)
        call.respond(getUserInfo(call, user))
    }
     suspend fun impersonateUser(call: ApplicationCall) {
        val session = call.principal<OAuthSession>()!!
        val impersonatedUsersCn = Strings.nullToEmpty(call.parameters["userToImpersonate"]).replace("@", "!")
        val originalUser = userLookupService.lookupUserByCn(session.userCn)
        val userToImpersonate = userLookupService.lookupUserByCn(impersonatedUsersCn)
        val originalUserWithImpersonatedRoles = originalUser.copy(
            memberOfCNs = userToImpersonate.memberOfCNs,
            firstName = "Impersonating " + userToImpersonate.firstName,
            lastName = userToImpersonate.lastName)
        val userInfoResponse = getUserInfo(call, originalUserWithImpersonatedRoles)
        userInfoResponse.impersonatedUserCn = impersonatedUsersCn
        call.respond(userInfoResponse)
    }

    @Suppress("PropertyName")
    @Serializable
    data class UserInfoResponse(
        val delta_ldap_user: LdapUser,
        val saml_token: String,
        val delta_user_roles: MemberOfToDeltaRolesMapper.Roles,
        val expires_at_epoch_second: Long,
        val is_sso: Boolean,
        var impersonatedUserCn: String? = null,
    )
    //add check for user is admin
}
