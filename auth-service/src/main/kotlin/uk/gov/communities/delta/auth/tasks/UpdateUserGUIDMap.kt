package uk.gov.communities.delta.auth.tasks

import org.jetbrains.annotations.Blocking
import org.slf4j.LoggerFactory
import uk.gov.communities.delta.auth.config.LDAPConfig
import uk.gov.communities.delta.auth.repositories.DbPool
import uk.gov.communities.delta.auth.repositories.LdapRepository
import uk.gov.communities.delta.auth.repositories.getNewModeObjectGuidString
import uk.gov.communities.delta.auth.repositories.searchPaged
import java.sql.Connection
import java.util.*
import javax.naming.directory.SearchControls
import kotlin.time.Duration.Companion.minutes

/*
 * Update the user_guid_map table to contain latest up to date userGUIDs and userCNs from Active Directory
 */
class UpdateUserGUIDMap(
    private val ldapConfig: LDAPConfig,
    private val dbPool: DbPool,
) : AuthServiceTask("UpdateUserGUIDMap") {
    private val logger = LoggerFactory.getLogger(javaClass)

    // Tasks are run separately anyway
    @Suppress("BlockingMethodInNonBlockingContext")
    override suspend fun execute() {
        val userGUIDs = fetchUserGuids()
        insertIntoDatabase(userGUIDs)
        logger.info("UpdateUserGUIDMap complete")
    }

    @Blocking
    private fun fetchUserGuids(): List<UserGuidMapTableRow> {
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
            val objectGuid = UUID.fromString(it.getNewModeObjectGuidString())
            UserGuidMapTableRow(cn, objectGuid)
        }
        ctx.close()
        logger.info("Read {} users in new mode from AD", users.size)
        return users
    }

    private fun ldapSearchControls(): SearchControls {
        val searchControls = SearchControls()
        searchControls.searchScope = SearchControls.ONELEVEL_SCOPE
        searchControls.timeLimit = 2.minutes.inWholeMilliseconds.toInt()
        searchControls.returningAttributes = arrayOf("cn", "objectGUID")
        return searchControls
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
            val ps = prepareStatement("INSERT INTO user_guid_map (user_cn, user_guid) VALUES (?, ?::UUID)")

            for (user in usersBatch) {
                ps.setString(1, user.userCN)
                ps.setObject(2, user.userGUID)
                ps.addBatch()
                ps.clearParameters()
            }
            ps.executeBatch()
            ps.close()
        }
    }

    private data class UserGuidMapTableRow(val userCN: String, val userGUID: UUID)
}
