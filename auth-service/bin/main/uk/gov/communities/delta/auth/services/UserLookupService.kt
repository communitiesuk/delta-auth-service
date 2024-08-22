package uk.gov.communities.delta.auth.services

import kotlinx.coroutines.Deferred
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import org.slf4j.LoggerFactory
import uk.gov.communities.delta.auth.plugins.NoUserException
import uk.gov.communities.delta.auth.repositories.LdapRepository
import uk.gov.communities.delta.auth.repositories.LdapUser
import java.util.*
import javax.naming.NameNotFoundException

class UserLookupService(
    private val userDnFormat: String,
    private val ldapServiceUserBind: LdapServiceUserBind,
    private val ldapRepository: LdapRepository,
    private val organisationService: OrganisationService,
    private val accessGroupsService: AccessGroupsService,
    private val memberOfToDeltaRolesMapperFactory: MemberOfToDeltaRolesMapperFactory,
) {
    private val logger = LoggerFactory.getLogger(javaClass)

    suspend fun lookupUserByCN(userCN: String): LdapUser {
        val userDN = userDnFormat.format(userCN)
        logger.atInfo().addKeyValue("userDN", userDN).log("Looking up user in AD")
        try {
            return ldapServiceUserBind.useServiceUserBind {
                ldapRepository.mapUserFromContext(it, userDN)
            }
        } catch (e: NameNotFoundException) {
            logger.atInfo().addKeyValue("userDN", userDN).log("User not found in Active Directory", e)
            throw NoUserException("No user with dn $userDN")
        }
    }

    suspend fun lookupUserByGUID(userGUID: UUID): LdapUser {
        logger.atInfo().log("Looking up user with GUID {} in AD ", userGUID)
        try {
            return ldapServiceUserBind.useServiceUserBind {
                ldapRepository.mapUserFromContext(it, userGUID)
            }
        } catch (e: NoUserException) {
            throw NoUserException("No user with GUID $userGUID")
        }
    }

    suspend fun lookupCurrentUser(session: OAuthSession): LdapUser {
        return lookupUserByGUID(session.userGUID)
    }

    suspend fun lookupCurrentUserAndLoadRoles(session: OAuthSession): LdapUserWithRoles {
        return lookupUserByGUIDAndLoadRoles(session.userGUID)
    }

    private suspend fun loadUserRoles(user: Deferred<LdapUser>): LdapUserWithRoles = coroutineScope {
        val allOrganisations = async { organisationService.findAllNamesAndCodes() }
        val allAccessGroups = async { accessGroupsService.getAllAccessGroups() }

        val awaitedUser = user.await()
        val roles = memberOfToDeltaRolesMapperFactory(
            awaitedUser.getGUID(),
            allOrganisations.await(),
            allAccessGroups.await()
        ).map(awaitedUser.memberOfCNs)

        LdapUserWithRoles(awaitedUser, roles)
    }

    suspend fun lookupUserByGUIDAndLoadRoles(guid: UUID): LdapUserWithRoles = coroutineScope {
        val user = async { lookupUserByGUID(guid) }
        loadUserRoles(user)
    }
}
