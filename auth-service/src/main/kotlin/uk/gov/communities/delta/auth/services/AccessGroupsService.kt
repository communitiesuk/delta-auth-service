package uk.gov.communities.delta.auth.services

import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import org.slf4j.LoggerFactory
import uk.gov.communities.delta.auth.config.LDAPConfig
import javax.naming.directory.Attributes
import javax.naming.directory.SearchControls
import kotlin.time.Duration.Companion.seconds


@Serializable
data class AccessGroup(
    val name: String,
    val classification: String?,
    val registrationDisplayName: String?,
    val enableOnlineRegistration: Boolean,
    val enableInternalUser: Boolean,
)


class AccessGroupsService(private val ldapService: LdapService, val config: LDAPConfig) {
    private val logger = LoggerFactory.getLogger(javaClass)

    companion object {
        private const val PAGE_SIZE = 200
    }

    suspend fun getAllAccessGroups(): List<AccessGroup> {
        val startTime = System.currentTimeMillis()

        return ldapService.useServiceUserBind { ctx ->
            val accessGroups =
                ctx.searchPaged(config.accessGroupContainerDn, "(objectClass=group)", searchControls(), PAGE_SIZE) {
                    val cn = it.get("cn").get() as String

                    if (DELTA_SYSTEM_ROLES.contains(cn) || DELTA_EXTERNAL_ROLES.contains(cn)) {
                        null
                    } else {
                        val info = it.getInfo()
                        AccessGroup(
                            cn,
                            it.getClassification(),
                            info.registrationDisplayName,
                            info.enableOnlineRegistration,
                            info.enableInternalUser
                        )
                    }
                }

            logger.atInfo().addKeyValue("accessGroupCount", accessGroups.size)
                .addKeyValue("durationMs", System.currentTimeMillis() - startTime)
                .log("Retrieved Access Groups from AD")
            return@useServiceUserBind accessGroups
        }
    }

    private fun searchControls(): SearchControls {
        val searchControls = SearchControls()
        searchControls.searchScope = SearchControls.ONELEVEL_SCOPE
        searchControls.timeLimit = 30.seconds.inWholeMilliseconds.toInt()
        searchControls.returningAttributes = arrayOf("cn", "description", "info")
        return searchControls
    }

    private val validClassifications = listOf("statistics", "grants", "other")
    private fun Attributes.getClassification(): String? {
        val description = get("description")?.get() as String? ?: return null
        return if (validClassifications.contains(description)) description else null
    }

    @Serializable
    data class AccessGroupInfo(
        val registrationDisplayName: String? = null,
        val enableOnlineRegistration: Boolean = false,
        val enableInternalUser: Boolean = false,
    )

    private fun Attributes.getInfo(): AccessGroupInfo {
        val cn = get("cn").get() as String
        val info = (get("info")?.get() as? String)?.let {
            try {
                Json.decodeFromString<AccessGroupInfo>(it)
            } catch (e: Exception) {
                logger.error("Failed to parse info attribute for access group, ignoring {} {}", cn, it, e)
                null
            }
        }
        return info ?: AccessGroupInfo()
    }
}
