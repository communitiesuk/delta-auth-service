package uk.gov.communities.delta.auth.services

import org.slf4j.LoggerFactory
import uk.gov.communities.delta.auth.repositories.LdapRepository
import uk.gov.communities.delta.auth.repositories.LdapUser
import javax.naming.NameNotFoundException

class UserLookupService(
    private val config: Configuration,
    private val ldapServiceUserBind: LdapServiceUserBind,
    private val ldapRepository: LdapRepository,
) {
    private val logger = LoggerFactory.getLogger(javaClass)

    data class Configuration(
        val userDnFormat: String,
        val bindUserDn: String,
        val bindUserPassword: String,
    )

    suspend fun userExists(cn: String): Boolean {
        return try {
            lookupUserByCn(cn)
            true
        } catch (e: NameNotFoundException) {
            false
        }
    }

    suspend fun lookupUserByCn(cn: String): LdapUser {
        val dn = config.userDnFormat.format(cn)
        return lookupUserByDN(dn)
    }

    suspend fun lookupUserByDN(dn: String): LdapUser {
        logger.atInfo().addKeyValue("userDN", dn).log("Looking up user in AD")
        return ldapServiceUserBind.useServiceUserBind {
            ldapRepository.mapUserFromContext(it, dn)
        }
    }
}
