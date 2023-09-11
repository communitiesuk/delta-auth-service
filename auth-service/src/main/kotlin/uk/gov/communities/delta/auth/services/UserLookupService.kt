package uk.gov.communities.delta.auth.services

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.slf4j.LoggerFactory
import javax.naming.NameNotFoundException

class UserLookupService(
    private val config: Configuration,
    private val ldapService: LdapService,
) {
    private val logger = LoggerFactory.getLogger(javaClass)

    data class Configuration(
        val userDnFormat: String,
        val bindUserDn: String,
        val bindUserPassword: String,
    )

    suspend fun userExists(cn: String) :Boolean {
        return try {
            lookupUserByCn(cn)
            true
        } catch (e :NameNotFoundException) {
            false
        }
    }

    suspend fun lookupUserByCn(cn: String): LdapUser {
        logger.atInfo().addKeyValue("username", cn).log("Looking up user in AD")
        val dn = config.userDnFormat.format(cn)
        return withContext(Dispatchers.IO) {
            val ctx = ldapService.bind(config.bindUserDn, config.bindUserPassword, poolConnection = true)
            try {
                ldapService.mapUserFromContext(ctx, dn)
            } finally {
                ctx.close()
            }
        }
    }
}
