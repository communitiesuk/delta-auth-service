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
        val oldUserGuids = fetchOldModeUserGuids()
        val newUserGuids = fetchNewModeUserGuids()

        val guidMapTableRows = constructUserGuidMapTableRows(oldUserGuids, newUserGuids)

        insertIntoDatabase(guidMapTableRows)
        logger.info("UpdateUserGUIDMap complete")
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
        logger.info("Read {} users in old mode from AD", users.size)
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
        logger.info("Read {} users in new mode from AD", users.size)
        return users
    }

    private fun ldapSearchControls(): SearchControls {
        val searchControls = SearchControls()
        searchControls.searchScope = SearchControls.ONELEVEL_SCOPE
        searchControls.timeLimit = 2.minutes.inWholeMilliseconds.toInt()
        searchControls.returningAttributes = arrayOf("cn", "objectGUID", "imported-guid")
        return searchControls
    }

    private fun constructUserGuidMapTableRows(
        oldGuids: List<UserGuid>,
        newGuids: List<UserGuid>,
    ): List<UserGuidMapTableRow> {
        val newGuidsMap = newGuids.associateBy { it.cn }.mapValues { it.value.guid }
        return oldGuids.map {
            UserGuidMapTableRow(
                it.cn,
                oldGuid = it.guid,
                newGuid = newGuidsMap.getOrElse(
                    it.cn
                ) { throw RuntimeException("No new GUID found for user " + it.cn) }
            )
        }
    }

    @Blocking
    private fun insertIntoDatabase(rows: List<UserGuidMapTableRow>) {
        dbPool.connection().use { conn ->
            logger.info("Truncating table to delete existing rows")
            val truncate = conn.prepareStatement("TRUNCATE TABLE user_guid_map")
            truncate.execute()
            truncate.close()

            logger.info("Starting insert of {} rows into user_guid_map", rows.size)
            conn.batchInsert(rows)

            conn.commit()
        }
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
