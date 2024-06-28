package uk.gov.communities.delta.auth.controllers.internal

import com.google.common.base.Strings
import io.ktor.http.*
import io.ktor.server.application.*
import io.ktor.server.auth.*
import io.ktor.server.plugins.callid.*
import io.ktor.server.response.*
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.withContext
import kotlinx.serialization.Serializable
import org.slf4j.LoggerFactory
import uk.gov.communities.delta.auth.config.DeltaConfig
import uk.gov.communities.delta.auth.config.LDAPConfig
import uk.gov.communities.delta.auth.plugins.ApiError
import uk.gov.communities.delta.auth.plugins.UserVisibleServerError
import uk.gov.communities.delta.auth.repositories.LdapUser
import uk.gov.communities.delta.auth.saml.SAMLTokenService
import uk.gov.communities.delta.auth.services.*
import java.util.*

class RefreshUserInfoController(
    private val userLookupService: UserLookupService,
    private val userGUIDMapService: UserGUIDMapService,
    private val samlTokenService: SAMLTokenService,
    private val accessGroupsService: AccessGroupsService,
    private val organisationService: OrganisationService,
    private val memberOfToDeltaRolesMapperFactory: MemberOfToDeltaRolesMapperFactory,
    private val oAuthSessionService: OAuthSessionService,
    private val userAuditService: UserAuditService,
) {
    private val logger = LoggerFactory.getLogger(javaClass)

    private suspend fun getUserInfo(call: ApplicationCall, user: LdapUser): UserInfoResponse {
        val session = call.principal<OAuthSession>()!!
        return coroutineScope {
            val allOrganisations = async { organisationService.findAllNamesAndCodes() }
            val allAccessGroups = async { accessGroupsService.getAllAccessGroups() }

            val samlToken = samlTokenService.samlTokenForSession(session, user)

            val roles = memberOfToDeltaRolesMapperFactory(
                user.getGUID(), allOrganisations.await(), allAccessGroups.await()
            ).map(user.memberOfCNs)

            logger.info("Retrieved updated user info")
            UserInfoResponse(user, samlToken.token, roles, samlToken.expiry.epochSecond, session.isSso)
        }
    }

    suspend fun refreshUserInfo(call: ApplicationCall) {
        val session = call.principal<OAuthSession>()!!
        ensureNotAlreadyImpersonating(session)
        val user = userLookupService.lookupCurrentUser(session)
        call.respond(getUserInfo(call, user))
    }

    suspend fun impersonateUser(call: ApplicationCall) {
        val session = call.principal<OAuthSession>()!!
        ensureNotAlreadyImpersonating(session)

        var impersonatedUsersCn = LDAPConfig.emailToCN(call.parameters["userToImpersonate"])
        val impersonatedUserGUIDString = call.parameters["userToImpersonateGUID"].orEmpty()
        val impersonatedUserGUID: UUID

        // During transition from userCN to userGUID exactly one should be non-empty
        // TODO DT-1022 - simplify this to just get GUID from call
        if (Strings.isNullOrEmpty(impersonatedUserGUIDString)) {
            if (Strings.isNullOrEmpty(impersonatedUsersCn)) throw UserVisibleServerError(
                "impersonating_user_no_user_cn_or_guid",
                "User CN and GUID both not present on impersonating_user",
                "Something went wrong, please try again"
            )
            impersonatedUserGUID = userGUIDMapService.getGUIDFromCN(impersonatedUsersCn)
        } else {
            if (!Strings.isNullOrEmpty(impersonatedUsersCn)) throw UserVisibleServerError(
                "impersonating_user_both_user_cn_and_guid",
                "User CN and GUID both present on impersonating_user",
                "Something went wrong, please try again"
            )
            impersonatedUserGUID = UUID.fromString(impersonatedUserGUIDString)
        }
        val userToImpersonate = userLookupService.lookupUserByGUID(impersonatedUserGUID)
        impersonatedUsersCn = userToImpersonate.cn

        val originalUser = userLookupService.lookupCurrentUser(session)
        if (!originalUser.memberOfCNs.contains(DeltaConfig.DATAMART_DELTA_ADMIN) || !originalUser.accountEnabled) {
            logger.atWarn().log("User does not have the necessary permissions to impersonate this user")
            throw ApiError(
                HttpStatusCode.Forbidden,
                "forbidden",
                "User is not an enabled admin",
                "You do not have the necessary permissions to do this"
            )
        }
        val rolesToTakeOn = userToImpersonate.memberOfCNs.filter { !it.startsWith(DeltaSystemRole.PERSONAL_DATA_OWNERS.adCn()) }
        val originalUserWithImpersonatedRoles = originalUser.copy(
            memberOfCNs = rolesToTakeOn,
        )
        val userInfoResponse = getUserInfo(call, originalUserWithImpersonatedRoles)
        userInfoResponse.impersonatedUserCn = impersonatedUsersCn
        userInfoResponse.impersonatedUserGuid = userToImpersonate.javaUUIDObjectGuid
        withContext(Dispatchers.IO) {
            oAuthSessionService.updateWithImpersonatedGUID(
                session.id,
                impersonatedUserGUID,
            )
        }
        userAuditService.insertImpersonatingUserAuditRow(
            session,
            impersonatedUserGUID,
            call.callId!!
        )
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
        var impersonatedUserGuid: String? = null,
    )

    private fun ensureNotAlreadyImpersonating(session: OAuthSession) {
        if (session.impersonatedUserGUID != null) {
            throw ApiError(
                HttpStatusCode.Forbidden,
                "forbidden",
                "User impersonating another user",
                "Not allowed while impersonating"
            )
        }
    }
}
