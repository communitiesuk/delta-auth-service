package uk.gov.communities.delta.auth.services

import kotlinx.coroutines.Deferred
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import org.slf4j.LoggerFactory
import uk.gov.communities.delta.auth.config.LDAPConfig
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

    suspend fun userIfUserWithEmailExists(email: String): LdapUser? {
        return try {
            lookupUserByEmail(email)
        } catch (e: LdapRepository.NoUserException) {
            null
        }
    }

    suspend fun lookupUserByEmail(email: String): LdapUser {
        val cn = LDAPConfig.emailToCN(email)
        return lookupUserByCn(cn)
    }

    suspend fun lookupUserByCn(cn: String): LdapUser {
        // TODO DT-1022 - delete/combine with above once not used
        val dn = userDnFormat.format(cn)
        return lookupUserByDN(dn)
    }

    suspend fun lookupUserByDN(dn: String): LdapUser {
        logger.atInfo().addKeyValue("userDN", dn).log("Looking up user in AD")
        try {
            return ldapServiceUserBind.useServiceUserBind {
                ldapRepository.mapUserFromContext(it, dn)
            }
        } catch (e: NameNotFoundException) {
            throw LdapRepository.NoUserException("No user with dn $dn")
        }
    }

    suspend fun lookupUserByGUID(userGUID: UUID): LdapUser {
        logger.atInfo().addKeyValue("userGUID", userGUID).log("Looking up user in AD")
        try {
            return ldapServiceUserBind.useServiceUserBind {
                ldapRepository.mapUserFromContext(it, userGUID)
            }
        } catch (e: LdapRepository.NoUserException) {
            throw LdapRepository.NoUserException("No user with GUID $userGUID")
        }
    }

    suspend fun lookupCurrentUser(session: OAuthSession): LdapUser {
        return if (session.userGUID != null)  // TODO DT-976-2 - no longer need this if
            lookupUserByGUID(session.userGUID)
        else
            lookupUserByCn(session.userCn)
    }

    suspend fun lookupCurrentUserAndLoadRoles(session: OAuthSession): LdapUserWithRoles {
        return if (session.userGUID != null) // TODO DT-976-2 - no longer need this if
            lookupUserByGUIDAndLoadRoles(session.userGUID)
        else
            lookupUserByCNAndLoadRoles(session.userCn)
    }

    private suspend fun loadUserRoles(user: Deferred<LdapUser>): LdapUserWithRoles = coroutineScope {
        val allOrganisations = async { organisationService.findAllNamesAndCodes() }
        val allAccessGroups = async { accessGroupsService.getAllAccessGroups() }

        val awaitedUser = user.await()
        val roles = memberOfToDeltaRolesMapperFactory(
            awaitedUser.cn,
            allOrganisations.await(),
            allAccessGroups.await()
        ).map(awaitedUser.memberOfCNs)

        LdapUserWithRoles(awaitedUser, roles)
    }

    // TODO DT-1022 - no longer needed
    suspend fun loadUserRoles(user: LdapUser): LdapUserWithRoles = coroutineScope {
        val allOrganisations = async { organisationService.findAllNamesAndCodes() }
        val allAccessGroups = async { accessGroupsService.getAllAccessGroups() }

        val roles = memberOfToDeltaRolesMapperFactory(
            user.cn,
            allOrganisations.await(),
            allAccessGroups.await()
        ).map(user.memberOfCNs)

        LdapUserWithRoles(user, roles)
    }

    suspend fun lookupUserByGUIDAndLoadRoles(guid: UUID): LdapUserWithRoles = coroutineScope {
        val user = async { lookupUserByGUID(guid) }
        loadUserRoles(user)
    }

    suspend fun lookupUserByCNAndLoadRoles(cn: String): LdapUserWithRoles = coroutineScope {
        // TODO DT-1022 - delete once not used
        val user = async { lookupUserByCn(cn) }
        loadUserRoles(user)
    }
}
