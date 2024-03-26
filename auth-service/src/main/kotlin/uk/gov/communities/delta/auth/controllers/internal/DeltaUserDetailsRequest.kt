package uk.gov.communities.delta.auth.controllers.internal

import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import uk.gov.communities.delta.auth.config.LDAPConfig
import uk.gov.communities.delta.auth.services.*

class DeltaUserPermissionsRequestMapper(
    private val organisationService: OrganisationService,
    private val accessGroupsService: AccessGroupsService,
) {
    class BadInput(message: String) : Exception(message)

    suspend fun deltaRequestToUserPermissions(userDetailsRequest: DeltaUserDetailsRequest): DeltaUserPermissions {
        val pair = allAccessGroupsAndOrgs()
        val allOrgs = pair.first.associateBy { it.code }
        val allAccessGroups = pair.second.associateBy { it.name }

        val organisations = userDetailsRequest.organisations.map {
            allOrgs[it] ?: throw BadInput("Unknown organisation $it")
        }.toSet()
        val roles = userDetailsRequest.roles.map {
//            DeltaSystemRole.fromString(it.removePrefix(LDAPConfig.DATAMART_DELTA_PREFIX))
//                ?: throw BadInput("Invalid system role $it") // qq
            DeltaSystemRole.USER
        }.toSet()
        userDetailsRequest.accessGroups.forEach {
            if (allAccessGroups[it.removePrefix(LDAPConfig.DATAMART_DELTA_PREFIX)] == null) throw BadInput(
                "Unknown access group $it"
            )
        }
        val prefixedAccessGroupNamesSet = userDetailsRequest.accessGroups.toSet()

        userDetailsRequest.accessGroupDelegates.find { !prefixedAccessGroupNamesSet.contains(it) }
            ?.let { throw BadInput("Cannot be delegate of access group $it without being a member") }

        val accessGroups = userDetailsRequest.accessGroupOrganisations.map { entry ->
            if (!prefixedAccessGroupNamesSet.contains(entry.key)) throw BadInput("Access group in organisation map but not list ${entry.key}")
            entry.value.find { agOrg -> !organisations.any { agOrg == it.code } }?.let {
                throw BadInput("Cannot be member of organisation $it not in organisation list")
            }
            DeltaUserPermissions.AccessGroup(
                entry.key.removePrefix(LDAPConfig.DATAMART_DELTA_PREFIX),
                entry.value,
                userDetailsRequest.accessGroupDelegates.contains(entry.key)
            )
        }

        return DeltaUserPermissions(organisations, roles + DeltaSystemRole.USER, accessGroups)
    }

    private suspend fun allAccessGroupsAndOrgs(): Pair<List<OrganisationNameAndCode>, List<AccessGroup>> {
        return coroutineScope {
            val allOrganisations = async { organisationService.findAllNamesAndCodes() }
            val allAccessGroups = async { accessGroupsService.getAllAccessGroups() }
            Pair(allOrganisations.await(), allAccessGroups.await())
        }
    }
}

data class DeltaUserPermissions(
    val organisations: Set<OrganisationNameAndCode>,
    val roles: Set<DeltaSystemRole>,
    val accessGroups: List<AccessGroup>,
) {
    data class AccessGroup(val name: String, val organisationIds: List<String>, val isDelegate: Boolean)

    fun getADGroupCNs(): List<String> {
        val groups = mutableListOf<String>()
        organisations.forEach {
            groups.add("user-${it.code}")
        }
        accessGroups.forEach { accessGroup ->
            groups.add(accessGroup.name)
            accessGroup.organisationIds.forEach { groups.add("${accessGroup.name}-$it") }
            if (accessGroup.isDelegate) groups.add("delegate-${accessGroup.name}")
        }
        roles.forEach { role ->
            groups.add(role.adRoleName)
            organisations.forEach { orgCode ->
                groups.add("${role.adRoleName}-$orgCode")
            }
        }
        return groups.map { LDAPConfig.DATAMART_DELTA_PREFIX + it }
    }
}

@Serializable
data class DeltaUserDetailsRequest(
    @SerialName("id") val id: String, //This is the username in email form
    @SerialName("enabled") val enabled: Boolean, //Always false for user creation - not used anywhere yet
    @SerialName("email") val email: String,
    @SerialName("lastName") val lastName: String,
    @SerialName("firstName") val firstName: String,
    @SerialName("telephone") val telephone: String? = null,
    @SerialName("mobile") val mobile: String? = null,
    @SerialName("position") val position: String? = null,
    @SerialName("reasonForAccess") val reasonForAccess: String? = null,
    // All prefixed with datamart-delta
    @SerialName("accessGroups") val accessGroups: List<String>,
    @SerialName("accessGroupDelegates") val accessGroupDelegates: List<String>,
    @SerialName("accessGroupOrganisations") val accessGroupOrganisations: Map<String, List<String>>,
    @SerialName("roles") val roles: List<String>,
    @SerialName("externalRoles") val externalRoles: List<String>, //Not used anywhere yet - S151 Officer related
    @SerialName("organisations") val organisations: List<String>,
    @SerialName("comment") val comment: String? = null,
    @SerialName("classificationType") val classificationType: String? = null, //Not used anywhere yet
)
