package uk.gov.communities.delta.auth.controllers.internal

import io.ktor.http.*
import io.ktor.server.application.*
import io.ktor.server.auth.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import org.slf4j.LoggerFactory
import uk.gov.communities.delta.auth.config.LDAPConfig
import uk.gov.communities.delta.auth.plugins.ApiError
import uk.gov.communities.delta.auth.repositories.LdapUser
import uk.gov.communities.delta.auth.repositories.isInternal
import uk.gov.communities.delta.auth.services.*

class EditAccessGroupsController(
    private val userLookupService: UserLookupService,
    private val groupService: GroupService,
    private val organisationService: OrganisationService,
    private val accessGroupsService: AccessGroupsService,
    private val memberOfToDeltaRolesMapperFactory: MemberOfToDeltaRolesMapperFactory,
) {

    private val logger = LoggerFactory.getLogger(javaClass)

    fun route(route: Route) {
        route.post { updateUserAccessGroups(call) }
    }

    // This endpoint takes a single user cn, single access group cn and a list of organisation codes.
    // It will assign the user to that access group and the given list of organisations for that access group.
    suspend fun addUserToAccessGroup(call: ApplicationCall) {
        val session = call.principal<OAuthSession>()!!
        val callingUser = userLookupService.lookupUserByCn(session.userCn)

        val addGroupRequest = call.receive<DeltaUserSingleAccessGroupOrganisationsRequest>()
        val targetUser = userLookupService.lookupUserByCn(addGroupRequest.userToEditCn)

        val targetGroupName = addGroupRequest.accessGroupName
        val targetOrganisationCodes = addGroupRequest.organisationCodes

        val targetGroupADName = getGroupADName(targetGroupName, null)

        if (targetOrganisationCodes.isEmpty()) {
            logger.atInfo()
                .log("Adding user {} to access group {}", targetUser.cn, targetGroupADName)
        } else {
            logger.atInfo()
                .log(
                    "Adding user {} to access group {} and organisations {}",
                    targetUser.cn,
                    targetGroupADName,
                    targetOrganisationCodes
                )
        }

        val allAccessGroups = accessGroupsService.getAllAccessGroups()
        val allOrganisationCodes = organisationService.findAllNamesAndCodes().map { it.code }
        validateSingleGroupRequest(
            allAccessGroups.map { it.name },
            targetGroupName,
            callingUser
        )
        validateOrganisationRequest(
            allOrganisationCodes,
            targetOrganisationCodes
        )

        if (targetUser.memberOfCNs.contains(targetGroupADName)) {
            logger.atWarn()
                .log("User {} already member of access group {}", targetUser.cn, targetGroupADName)
        } else {
            groupService.addUserToGroup(
                targetUser.cn,
                targetUser.dn,
                targetGroupADName,
                call,
                session,
            )
        }
        targetOrganisationCodes.forEach {
            val targetGroupOrgADName = getGroupADName(targetGroupName, it)
            if (targetUser.memberOfCNs.contains(targetGroupOrgADName)) {
                logger.atWarn()
                    .log("User {} already member of access group {}", targetUser.cn, targetGroupOrgADName)
            } else {
                groupService.addUserToGroup(
                    targetUser.cn,
                    targetUser.dn,
                    targetGroupOrgADName,
                    call,
                    session,
                )
            }
        }

        return call.respond(mapOf("message" to "User ${targetUser.cn} added to access group $targetGroupName and organisations ${targetOrganisationCodes}."))
    }


    // This endpoint takes a single user cn and a single access group cn.
    // It will remove the user from the given access group, including any organisation associations.
    suspend fun removeUserFromAccessGroup(call: ApplicationCall) {
        val session = call.principal<OAuthSession>()!!
        val callingUser = userLookupService.lookupUserByCn(session.userCn)

        val removeGroupRequest = call.receive<DeltaUserSingleAccessGroupRequest>()
        val targetUser = userLookupService.lookupUserByCn(removeGroupRequest.userToEditCn)

        val targetGroupName = removeGroupRequest.accessGroupName

        val targetGroupADName = getGroupADName(targetGroupName, null)

        logger.atInfo()
            .log("Removing user {} from access group {}", targetUser.cn, targetGroupADName)

        val allAccessGroups = accessGroupsService.getAllAccessGroups()
        validateSingleGroupRequest(
            allAccessGroups.map { it.name },
            targetGroupName,
            callingUser
        )

        if (targetUser.memberOfCNs.contains(targetGroupADName)) {
            for (groupName in targetUser.memberOfCNs) {
                if (groupName.startsWith(targetGroupADName)) {
                    groupService.removeUserFromGroup(
                        targetUser.cn,
                        targetUser.dn,
                        groupName,
                        call,
                        session,
                    )
                }
            }
            return call.respond(mapOf("message" to "User ${targetUser.cn} removed from access group ${targetGroupName}."))
        } else {
            logger.atWarn()
                .log("User {} already not member of access group {}", targetUser.cn, targetGroupADName)
            return call.respond(mapOf("message" to "User ${targetUser.cn} already not member of access group ${targetGroupName}."))
        }
    }

    // This endpoint takes a map of access groups or organisations and a list of organisations. The map should contain all
    // access groups the user could potentially assign themselves to. Groups the user has selected should contain a list of
    // associated organisations, groups the user has not selected should contain an empty list. The list of organisations
    // should contain the organisations the user has chosen to be part of from the organisations available to them.
    suspend fun updateUserAccessGroups(call: ApplicationCall) {
        val session = call.principal<OAuthSession>()!!
        val callingUser = userLookupService.lookupUserByCn(session.userCn)
        logger.atInfo().log("Updating access groups for user {}", session.userCn)
        val userIsInternal = callingUser.isInternal()
        val allAccessGroups = accessGroupsService.getAllAccessGroups()

        val requestBodyObject = call.receive<DeltaUserOwnAccessGroups>()
        val selectedOrgs = requestBodyObject.userSelectedOrgs.toSet()
        val accessGroupRequestMap = stripDatamartPrefixFromKeys(requestBodyObject.accessGroupsRequest)

        validateUpdateAccessGroupsRequest(
            accessGroupRequestMap,
            selectedOrgs,
            allAccessGroups,
            userIsInternal,
            callingUser
        )

        val deltaRolesForUser = memberOfToDeltaRolesMapperFactory(
            callingUser.cn, organisationService.findAllNamesAndCodes(), allAccessGroups
        ).map(callingUser.memberOfCNs)
        val currentAccessGroups = deltaRolesForUser.accessGroups.associateBy({ it.name },
            { it.organisationIds })

        val accessGroupActions = generateAccessGroupActions(accessGroupRequestMap, currentAccessGroups, selectedOrgs)

        executeAccessGroupActions(accessGroupActions, null, callingUser, call)

        return call.respond(mapOf("message" to "Access groups have been updated. Any changes to your roles or access groups will take effect the next time you log in."))
    }

    fun validateSingleGroupRequest(
        allAccessGroupNames: List<String>,
        groupName: String,
        callingUser: LdapUser
    ) {
        if (!allAccessGroupNames.contains(groupName)) {
            throw ApiError(
                HttpStatusCode.BadRequest,
                "nonexistent_group",
                "Attempted to assign or remove user to/from access group that does not exist: $groupName",
            )
        }
        if (!callingUser.isInternal()) {
            throw ApiError(
                HttpStatusCode.Forbidden,
                "non_internal_user_altering_access_group_membership",
                "Non-internal user attempted to add or remove a user to/from access group: $groupName",
            )
        }
    }

    private fun validateOrganisationRequest(
        allOrganisationCodes: List<String>,
        orgCodes: List<String>
    ) {
        if (orgCodes.isNotEmpty() && !allOrganisationCodes.containsAll(orgCodes)) {
            throw ApiError(
                HttpStatusCode.BadRequest,
                "nonexistent_organisation",
                "Attempted to assign or remove user to/from access group organisation that does not exist",
            )
        }
    }

    private suspend fun validateUpdateAccessGroupsRequest(
        accessGroupRequestMap: Map<String, List<String>>,
        selectedOrgs: Set<String>,
        allAccessGroups: List<AccessGroup>,
        userIsInternal: Boolean,
        callingUser: LdapUser
    ) {
        validateAccessGroupRequest(
            accessGroupRequestMap,
            allAccessGroups,
            selectedOrgs,
            userIsInternal
        )
        validateOrganisationRequest(callingUser, selectedOrgs)
    }

    private suspend fun validateOrganisationRequest(
        callingUser: LdapUser,
        selectedOrgs: Set<String>
    ) {
        val userDomainOrgs = organisationService.findAllByEmail(callingUser.email).map { it.code }.toSet()
        for (org in selectedOrgs) {
            if (!userDomainOrgs.contains(org)) {
                throw ApiError(
                    HttpStatusCode.Forbidden,
                    "user_non_domain_organisation",
                    "User attempted to assign self to an organisation not in their domain: $org",
                )
            }
        }
    }

    private fun validateAccessGroupRequest(
        accessGroupRequestMap: Map<String, List<String>>,
        allAccessGroups: List<AccessGroup>,
        selectedOrgs: Set<String>,
        userIsInternal: Boolean
    ) {
        val allAccessGroupsMap = allAccessGroups.associateBy { it.name }

        for (requestedAccessGroup in accessGroupRequestMap) {
            val accessGroupData = allAccessGroupsMap.getOrElse(requestedAccessGroup.key) {
                throw ApiError(
                    HttpStatusCode.BadRequest,
                    "nonexistent_group",
                    "Request contained an access group that does not exist: "
                        + requestedAccessGroup.key,
                )
            }

            if (userIsInternal && !accessGroupData.enableInternalUser) {
                throw ApiError(
                    HttpStatusCode.Forbidden,
                    "internal_user_non_internal_group",
                    "Request for internal user contained a group not enabled for internal users: "
                        + requestedAccessGroup.key,
                )
            }

            if (!userIsInternal && !accessGroupData.enableOnlineRegistration) {
                throw ApiError(
                    HttpStatusCode.Forbidden,
                    "external_user_non_online_registration_group",
                    "Request for external user contained a group not enabled for online registration: "
                        + requestedAccessGroup.key,
                )
            }

            for (requestedGroupOrg in requestedAccessGroup.value) {
                if (!selectedOrgs.contains(requestedGroupOrg)) {
                    throw ApiError(
                        HttpStatusCode.Forbidden,
                        "user_non_selected_organisation_access_group",
                        "Request contained access group with organisation not in user's selected organisations: $requestedGroupOrg"
                    )
                }
            }
        }
    }

    fun generateAccessGroupActions(
        accessGroupsRequestMap: Map<String, List<String>>,
        currentAccessGroups: Map<String, List<String>>,
        selectedOrgs: Set<String>
    ): Set<AccessGroupAction> {
        val accessGroupActions = mutableSetOf<AccessGroupAction>()

        for (accessGroup in accessGroupsRequestMap) {
            val currentOrganisations = currentAccessGroups[accessGroup.key]
            val requestedOrganisations = accessGroup.value

            val userIsInAccessGroup = currentOrganisations != null
            if (userIsInAccessGroup) {
                val organisationsAfterModification = currentOrganisations!!.toMutableSet()
                for (requestedOrg in requestedOrganisations) {
                    if (organisationsAfterModification.add(requestedOrg)) {
                        accessGroupActions.add(AddAccessGroupOrganisationAction(accessGroup.key, requestedOrg))
                    }
                }
                for (currentOrg in currentOrganisations) {
                    if (!requestedOrganisations.contains(currentOrg) && selectedOrgs.contains(currentOrg)) {
                        accessGroupActions.add(RemoveAccessGroupOrganisationAction(accessGroup.key, currentOrg))
                        organisationsAfterModification.remove(currentOrg)
                    }
                }
                if (organisationsAfterModification.isEmpty()) {
                    accessGroupActions.add(RemoveAccessGroupAction(accessGroup.key))
                }
            } else {
                if (requestedOrganisations.isNotEmpty()) {
                    accessGroupActions.add(AddAccessGroupAction(accessGroup.key))
                    for (requestedOrg in requestedOrganisations) {
                        accessGroupActions.add(AddAccessGroupOrganisationAction(accessGroup.key, requestedOrg))
                    }
                }
            }
        }
        return accessGroupActions.toSet()
    }

    private suspend fun executeAccessGroupActions(
        accessGroupActions: Set<AccessGroupAction>,
        adminSession: OAuthSession?,
        userToAdd: LdapUser,
        call: ApplicationCall,
    ) {
        for (action in accessGroupActions) {
            if (action is AddAccessGroupAction || action is AddAccessGroupOrganisationAction) {
                logger.atInfo()
                    .log(
                        "Adding user {} to access group {}",
                        userToAdd.cn,
                        getGroupADName(action.accessGroupName, action.organisationCode)
                    )
                groupService.addUserToGroup(
                    userToAdd.cn,
                    userToAdd.dn,
                    getGroupADName(action.accessGroupName, action.organisationCode),
                    call,
                    adminSession
                )
            } else if (action is RemoveAccessGroupAction || action is RemoveAccessGroupOrganisationAction) {
                logger.atInfo()
                    .log(
                        "Removing user {} from access group {}",
                        userToAdd.cn,
                        getGroupADName(action.accessGroupName, action.organisationCode)
                    )
                groupService.removeUserFromGroup(
                    userToAdd.cn,
                    userToAdd.dn,
                    getGroupADName(action.accessGroupName, action.organisationCode),
                    call,
                    adminSession
                )
            }
        }
    }

    private fun stripDatamartPrefixFromKeys(prefixedMap: Map<String, List<String>>): Map<String, List<String>> {
        val newMap = mutableMapOf<String, List<String>>()
        for (entry in prefixedMap.entries) {
            newMap[entry.key.removePrefix(LDAPConfig.DATAMART_DELTA_PREFIX)] = entry.value
        }
        return newMap.toMap()
    }

    sealed class AccessGroupAction(
        val accessGroupName: String,
        val organisationCode: String?,
    ) {
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other !is AccessGroupAction) return false
            if (this.javaClass != other.javaClass) return false

            return this.accessGroupName == other.accessGroupName && this.organisationCode == other.organisationCode
        }

        override fun hashCode(): Int {
            var result = javaClass.hashCode()
            result = 31 * result + accessGroupName.hashCode()
            result = 31 * result + (organisationCode?.hashCode() ?: 0)
            return result
        }
    }

    private fun getGroupADName(targetGroupName: String, targetOrganisationCode: String?) =
        LDAPConfig.DATAMART_DELTA_PREFIX + targetGroupName + if (targetOrganisationCode.isNullOrEmpty()) "" else "-$targetOrganisationCode"

    class AddAccessGroupOrganisationAction(accessGroupName: String, organisationCode: String) :
        AccessGroupAction(accessGroupName, organisationCode)

    class AddAccessGroupAction(accessGroupName: String) :
        AccessGroupAction(accessGroupName, null)

    class RemoveAccessGroupOrganisationAction(accessGroupName: String, organisationCode: String) :
        AccessGroupAction(accessGroupName, organisationCode)

    class RemoveAccessGroupAction(accessGroupName: String) :
        AccessGroupAction(accessGroupName, null)

    @Serializable
    data class DeltaUserOwnAccessGroups(
        val accessGroupsRequest: Map<String, List<String>>,
        val userSelectedOrgs: List<String>,
    )

    @Serializable
    data class DeltaUserSingleAccessGroupRequest(
        @SerialName("userToEditCn") val userToEditCn: String,
        @SerialName("accessGroupName") val accessGroupName: String,
    )

    @Serializable
    data class DeltaUserSingleAccessGroupOrganisationsRequest(
        @SerialName("userToEditCn") val userToEditCn: String,
        @SerialName("accessGroupName") val accessGroupName: String,
        @SerialName("organisationCodes") val organisationCodes: List<String>,
    )
}
