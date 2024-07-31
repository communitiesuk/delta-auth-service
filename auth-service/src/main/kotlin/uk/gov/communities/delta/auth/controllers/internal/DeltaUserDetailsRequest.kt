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

    suspend fun deltaRequestToUserPermissions(userDetailsRequest: DeltaUserDetailsRequest): DeltaUserPermissions {
        return coroutineScope {
            val allOrganisations = async { organisationService.findAllNamesAndCodes() }
            val allAccessGroups = async { accessGroupsService.getAllAccessGroups() }
            DeltaUserPermissions.fromUserDetailsRequest(
                userDetailsRequest,
                allAccessGroups.await().associateBy { it.prefixedName },
                allOrganisations.await().associateBy { it.code },
            )
        }
    }
}

data class DeltaUserPermissions(
    val organisations: Set<OrganisationNameAndCode>,
    val roles: Set<DeltaSystemRole>,
    val accessGroups: Set<AccessGroupRole>,
) {
    companion object {
        class BadInput(message: String) : Exception(message)

        fun fromUserDetailsRequest(
            userDetailsRequest: DeltaUserDetailsRequest,
            allAccessGroups: Map<String, AccessGroup>,
            allOrganisations: Map<String, OrganisationNameAndCode>,
        ): DeltaUserPermissions {
            val organisations = userDetailsRequest.organisations.map {
                allOrganisations[it] ?: throw BadInput("Unknown organisation $it")
            }.toSet()

            val roles = userDetailsRequest.roles.map {
                DeltaSystemRole.fromString(it.removePrefix(LDAPConfig.DATAMART_DELTA_PREFIX))
                    ?: throw BadInput("Invalid system role $it")
            }.toSet()

            // Access groups must all exist
            userDetailsRequest.accessGroups.forEach {
                if (allAccessGroups[it.removePrefix(LDAPConfig.DATAMART_DELTA_PREFIX)] == null) throw BadInput(
                    "Unknown access group $it"
                )
            }
            // Keys of the (access group -> organisations) map must all be in the access groups list
            val prefixedAccessGroupNamesSet = userDetailsRequest.accessGroups.toSet()
            userDetailsRequest.accessGroupOrganisations.forEach { entry ->
                if (!prefixedAccessGroupNamesSet.contains(entry.key)) throw BadInput("Access group in organisation map but not list ${entry.key}")
            }
            // User must be a member of all delegated access groups
            userDetailsRequest.accessGroupDelegates.find { !prefixedAccessGroupNamesSet.contains(it) }
                ?.let { throw BadInput("Cannot be delegate of access group $it without being a member") }

            val accessGroups = userDetailsRequest.accessGroups.map { prefixedAccessGroupName ->
                val accessGroupName = prefixedAccessGroupName.removePrefix(LDAPConfig.DATAMART_DELTA_PREFIX)
                val accessGroup = allAccessGroups[accessGroupName]!!
                val accessGroupOrganisations = userDetailsRequest.accessGroupOrganisations[prefixedAccessGroupName]
                accessGroupOrganisations?.find { agOrg -> !organisations.any { agOrg == it.code } }?.let {
                    throw BadInput("Cannot be member of organisation $it for access group $prefixedAccessGroupName as not member of organisation")
                }
                AccessGroupRole(
                    accessGroupName,
                    accessGroup.registrationDisplayName,
                    accessGroup.classification,
                    accessGroupOrganisations ?: emptyList(),
                    userDetailsRequest.accessGroupDelegates.contains(prefixedAccessGroupName)
                )
            }.toSet()

            return DeltaUserPermissions(organisations, roles + DeltaSystemRole.USER, accessGroups)
        }
    }

    fun getADGroupCNs(): List<String> {
        if (!roles.contains(DeltaSystemRole.USER)) throw Exception("Cannot generate groups list for user that doesn't have the USER system role")
        val groups = mutableListOf<String>()
        accessGroups.forEach { accessGroup ->
            groups.add(accessGroup.name)
            accessGroup.organisationIds.forEach { groups.add("${accessGroup.name}-$it") }
            if (accessGroup.isDelegate) groups.add("delegate-${accessGroup.name}")
        }
        roles.forEach { role ->
            groups.add(role.adRoleName)
            organisations.forEach { org ->
                groups.add("${role.adRoleName}-${org.code}")
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
    @SerialName("userObjectGuid") val userObjectGuid: String? = null,
    @SerialName("isAdmin") val isAdmin: String? = null,
)
