package uk.gov.communities.delta.auth.tasks

import org.jetbrains.annotations.Blocking
import org.slf4j.LoggerFactory
import uk.gov.communities.delta.auth.config.LDAPConfig
import uk.gov.communities.delta.auth.repositories.*
import java.sql.Connection
import javax.naming.directory.SearchControls
import kotlin.time.Duration.Companion.minutes

/*
 * Update the user_guid_map database table by reading all users from Active Directory in both old and new GUID mode
 */
class UpdateUserGUIDMap(
    private val ldapConfig: LDAPConfig,
    private val dbPool: DbPool,
) : AuthServiceTask("UpdateUserGUIDMap") {
    private val logger = LoggerFactory.getLogger(javaClass)

    private val searchDn = ldapConfig.deltaUserDnFormat.removePrefix("CN=%s,")

    // Tasks are run separately anyway
    @Suppress("BlockingMethodInNonBlockingContext")
    override suspend fun execute() {
        logger.info("Starting UpdateUserGUIDMap")
        val oldUserGuids = fetchOldModeUserGuids()
        logger.info("Read {} users in old mode from AD", oldUserGuids.size)
        val newUserGuids = fetchNewModeUserGuids()
        logger.info("Read {} users in new mode from AD", newUserGuids.size)

        val newGuidsMap = newUserGuids.associateBy { it.cn }.mapValues { it.value.guid }
        val guidMapRows = oldUserGuids.map {
            UserGuidMapTableRow(
                it.cn,
                oldGuid = it.guid,
                newGuid = newGuidsMap.getOrElse(
                    it.cn
                ) { throw RuntimeException("No new GUID found for user " + it.cn) }
            )
        }
        logger.info("All users loaded")

        dbPool.connection().use { conn ->
            val truncate = conn.prepareStatement("TRUNCATE TABLE user_guid_map")
            truncate.execute()
            truncate.close()

            conn.batchInsert(guidMapRows)

            conn.commit()
        }
        logger.info("All rows inserted, done")
    }

    @Blocking
    private fun fetchOldModeUserGuids(): List<UserGuid> {
        val oldModeLdapRepository = LdapRepository(ldapConfig, LdapRepository.ObjectGUIDMode.OLD_MANGLED)
        val ctx = oldModeLdapRepository.bind(
            ldapConfig.authServiceUserDn,
            ldapConfig.authServiceUserPassword,
        )
        val users = ctx.searchPaged(
            searchDn,
            "(objectClass=user)",
            ldapSearchControls(),
            pageSize = 200,
        ) {
            val cn = it.get("cn").get() as String
            val mangledObjectGuid = it.getMangledDeltaObjectGUID()
            UserGuid(cn, mangledObjectGuid)
        }
        ctx.close()
        return users
    }

    @Blocking
    private fun fetchNewModeUserGuids(): List<UserGuid> {
        val oldModeLdapRepository = LdapRepository(ldapConfig, LdapRepository.ObjectGUIDMode.NEW_JAVA_UUID_STRING)
        val ctx = oldModeLdapRepository.bind(
            ldapConfig.authServiceUserDn,
            ldapConfig.authServiceUserPassword,
        )
        val searchDn = ldapConfig.deltaUserDnFormat.removePrefix("CN=%s,")
        val users = ctx.searchPaged(
            searchDn,
            "(objectClass=user)",
            ldapSearchControls(),
            pageSize = 200,
        ) {
            val cn = it.get("cn").get() as String
            val objectGuid = it.getNewModeObjectGuid().toString()
            UserGuid(cn, objectGuid)
        }
        ctx.close()
        return users
    }

    private fun ldapSearchControls(): SearchControls {
        val searchControls = SearchControls()
        searchControls.searchScope = SearchControls.ONELEVEL_SCOPE
        searchControls.timeLimit = 2.minutes.inWholeMilliseconds.toInt()
        searchControls.returningAttributes = arrayOf("cn", "objectGUID", "imported-guid")
        return searchControls
    }

    @Blocking
    private fun Connection.batchInsert(rows: List<UserGuidMapTableRow>) {
        for (usersBatch in rows.chunked(100)) {
            logger.debug("Inserting batch of {}", usersBatch.size)
            val ps = prepareStatement("INSERT INTO user_guid_map (cn, oldguid, newguid) VALUES (?, ?, ?::UUID)")

            for (user in usersBatch) {
                ps.setString(1, user.cn)
                ps.setString(2, user.oldGuid)
                ps.setString(3, user.newGuid)
                ps.addBatch()
                ps.clearParameters()
            }
            ps.executeBatch()
            ps.close()
        }
    }

    private data class UserGuid(val cn: String, val guid: String)
    private data class UserGuidMapTableRow(val cn: String, val oldGuid: String, val newGuid: String)
}
