package uk.gov.communities.delta.auth.services

import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import org.slf4j.LoggerFactory
import uk.gov.communities.delta.auth.repositories.LdapRepository
import uk.gov.communities.delta.auth.repositories.LdapUser
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

    suspend fun userExists(cn: String): Boolean {
        return try {
            lookupUserByCn(cn)
            true
        } catch (e: NameNotFoundException) {
            false
        }
    }

    suspend fun lookupUserByCn(cn: String): LdapUser {
        val dn = userDnFormat.format(cn)
        return lookupUserByDN(dn)
    }

    suspend fun lookupUserByDN(dn: String): LdapUser {
        logger.atInfo().addKeyValue("userDN", dn).log("Looking up user in AD")
        return ldapServiceUserBind.useServiceUserBind {
            ldapRepository.mapUserFromContext(it, dn)
        }
    }

    suspend fun lookupUserByCNAndLoadRoles(cn: String): LdapUserWithRoles = coroutineScope {
        val user = async { lookupUserByCn(cn) }
        val allOrganisations = async { organisationService.findAllNamesAndCodes() }
        val allAccessGroups = async { accessGroupsService.getAllAccessGroups() }

        val awaitedUser = user.await()
        val roles = memberOfToDeltaRolesMapperFactory(
            cn,
            allOrganisations.await(),
            allAccessGroups.await()
        ).map(awaitedUser.memberOfCNs)

        LdapUserWithRoles(awaitedUser, roles)
    }
}
