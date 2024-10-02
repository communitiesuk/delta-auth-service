package uk.gov.communities.delta.auth.services

import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import org.slf4j.LoggerFactory
import uk.gov.communities.delta.auth.config.LDAPConfig
import uk.gov.communities.delta.auth.config.LDAPConfig.Companion.DATAMART_DELTA_PREFIX
import uk.gov.communities.delta.auth.repositories.searchPaged
import javax.naming.NameNotFoundException
import javax.naming.directory.Attributes
import javax.naming.directory.SearchControls
import kotlin.time.Duration.Companion.seconds


data class AccessGroup(
    val prefixedName: String,
    val classification: String?,
    val registrationDisplayName: String?,
    val enableOnlineRegistration: Boolean,
    val enableInternalUser: Boolean,
) {
    val name = prefixedName.removePrefix(DATAMART_DELTA_PREFIX)
}

class AccessGroupsService(private val ldapServiceUserBind: LdapServiceUserBind, val config: LDAPConfig) {
    private val logger = LoggerFactory.getLogger(javaClass)

    companion object {
        private const val PAGE_SIZE = 200
        private val VALID_ACCESS_GROUP_NAME_REGEX = Regex("^[a-z][a-z0-9\\-]+")
    }

    suspend fun getAllAccessGroups(): List<AccessGroup> {
        val startTime = System.currentTimeMillis()

        return ldapServiceUserBind.useServiceUserBind { ctx ->
            val accessGroups = ctx.searchPaged(
                config.accessGroupContainerDn,
                "(objectClass=group)",
                searchControls(),
                PAGE_SIZE,
                ::accessGroupFromAttributes
            )

            logger.atInfo().addKeyValue("accessGroupCount", accessGroups.size)
                .addKeyValue("durationMs", System.currentTimeMillis() - startTime)
                .log("Retrieved Access Groups from AD")
            return@useServiceUserBind accessGroups
        }
    }

    private fun accessGroupFromAttributes(attr: Attributes): AccessGroup? {
        val cn = attr.get("cn").get() as String

        if (DeltaSystemRole.ROLE_NAME_MAP.containsKey(cn) || DELTA_EXTERNAL_ROLES.contains(cn)) {
            return null
        } else {
            val info = attr.getInfo()
            return AccessGroup(
                cn,
                attr.getClassification(),
                info.registrationDisplayName,
                info.enableOnlineRegistration,
                info.enableInternalUser
            )
        }
    }

    suspend fun getAccessGroup(accessGroupName: String): AccessGroup? {

        checkAccessGroupPrefixIsValid(accessGroupName)
        checkAccessGroupNameIsValid(accessGroupName)

        return ldapServiceUserBind.useServiceUserBind { ctx ->
            try {
                accessGroupFromAttributes(
                    ctx.getAttributes(
                        "CN=$accessGroupName,${config.accessGroupContainerDn}",
                        arrayOf("cn", "description", "info")
                    )
                )
            } catch (ex: NameNotFoundException) {
                logger.warn("Access group not found in AD '$accessGroupName'")
                null
            }
        }
    }

    fun checkAccessGroupNameIsValid (accessGroupName: String) {
        if (!VALID_ACCESS_GROUP_NAME_REGEX.matches(accessGroupName)) throw IllegalArgumentException("Invalid access group name '$accessGroupName'")
    }

    fun checkAccessGroupPrefixIsValid (accessGroupPrefix: String) {
        if (accessGroupPrefix.startsWith(DATAMART_DELTA_PREFIX)) throw IllegalArgumentException("Invalid access group prefix '$accessGroupPrefix'")
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
