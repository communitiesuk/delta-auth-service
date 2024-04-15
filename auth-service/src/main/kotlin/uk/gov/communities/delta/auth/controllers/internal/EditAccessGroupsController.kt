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
        validateIsInternalUser(callingUser)

        val addGroupRequest = call.receive<DeltaUserSingleAccessGroupOrganisationsRequest>()
        val (targetUser, targetUserRoles) = userLookupService.lookupUserByCNAndLoadRoles(addGroupRequest.userToEditCn)

        val targetGroupName = addGroupRequest.accessGroupName
        val targetOrganisationCodes = addGroupRequest.organisationCodes

        logger.info(
            "Adding user {} to access group {} and organisations {}",
            targetUser.cn,
            targetGroupName,
            targetOrganisationCodes
        )

        validateAccessGroupExists(targetGroupName)
        validateUserInOrganisations(targetUserRoles, targetOrganisationCodes)

        val targetGroupADName = getGroupOrgADName(targetGroupName, null)
        if (targetUser.memberOfCNs.contains(targetGroupADName)) {
            logger.warn("User {} already member of access group {}", targetUser.cn, targetGroupADName)
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
            val targetGroupOrgADName = getGroupOrgADName(targetGroupName, it)
            if (targetUser.memberOfCNs.contains(targetGroupOrgADName)) {
                logger.warn(
                    "User {} already member of (access group, organisation) ({}, {})",
                    targetUser.cn,
                    targetGroupName,
                    it
                )
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
        validateIsInternalUser(callingUser)

        val removeGroupRequest = call.receive<DeltaUserSingleAccessGroupRequest>()
        val targetUser = userLookupService.lookupUserByCn(removeGroupRequest.userToEditCn)

        val targetGroupName = removeGroupRequest.accessGroupName
        validateAccessGroupExists(targetGroupName)

        val targetGroupADName = getGroupOrgADName(targetGroupName, null)

        logger.info("Removing user {} from access group {}", targetUser.cn, targetGroupADName)

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
            logger.warn("User {} already not member of access group {}", targetUser.cn, targetGroupADName)
            return call.respond(mapOf("message" to "User ${targetUser.cn} already not member of access group ${targetGroupName}."))
        }
    }

    private suspend fun validateAccessGroupExists(accessGroupName: String) =
        accessGroupsService.getAccessGroup(accessGroupName)
            ?: throw ApiError(
                HttpStatusCode.BadRequest,
                "nonexistent_group",
                "Access group does not exist: $accessGroupName",
            )

    private fun validateUserInOrganisations(
        targetUserRoles: MemberOfToDeltaRolesMapper.Roles,
        organisationCodes: List<String>,
    ) {
        for (orgCode in organisationCodes) {
            if (!targetUserRoles.organisations.any { it.code == orgCode }) {
                throw ApiError(
                    HttpStatusCode.BadRequest,
                    "user_not_member_of_organisation",
                    "Attempted to add user to organisation $orgCode for access group, but user is not member of organisation $orgCode",
                )
            }
        }
    }

    // This endpoint takes a map of access group names to lists of organisation codes. The map should contain all
    // access groups the user could potentially assign themselves to. Groups the user has selected should contain a list of
    // associated organisations, groups the user has not selected should contain an empty list.
    // A list of all "userSelectedOrgs" (organisation codes) that the access group request refers to should be provided as well,
    // membership of (access group, organisation) will be ignored for organisations not in this list.
    suspend fun updateUserAccessGroups(call: ApplicationCall) {
        val session = call.principal<OAuthSession>()!!
        val callingUser = userLookupService.lookupUserByCn(session.userCn)
        logger.info("Updating access groups for user {}", session.userCn)
        val userIsInternal = callingUser.isInternal()
        val allAccessGroups = accessGroupsService.getAllAccessGroups()

        val requestBodyObject = call.receive<DeltaUserOwnAccessGroups>()
        val selectedOrgs = requestBodyObject.userSelectedOrgs.toSet()
        val accessGroupRequestMap = stripDatamartPrefixFromKeys(requestBodyObject.accessGroupsRequest)

        val deltaRolesForUser = memberOfToDeltaRolesMapperFactory(
            callingUser.cn, organisationService.findAllNamesAndCodes(), allAccessGroups
        ).map(callingUser.memberOfCNs)

        validateUpdateAccessGroupsRequest(
            accessGroupRequestMap,
            selectedOrgs,
            allAccessGroups,
            userIsInternal,
            callingUser,
            deltaRolesForUser,
        )

        val currentAccessGroups = deltaRolesForUser.accessGroups.associateBy({ it.name }, { it.organisationIds })
        val accessGroupActions = generateAccessGroupActions(accessGroupRequestMap, currentAccessGroups, selectedOrgs)

        executeAccessGroupActions(accessGroupActions, null, callingUser, call)

        return call.respond(mapOf("message" to "Access groups have been updated. Any changes to your roles or access groups will take effect the next time you log in."))
    }

    fun validateIsInternalUser(callingUser: LdapUser) {
        if (!callingUser.isInternal()) {
            throw ApiError(
                HttpStatusCode.Forbidden,
                "non_internal_user_altering_access_group_membership",
                "Non-internal user attempted to add or remove a user to/from access group",
            )
        }
    }

    private suspend fun validateUpdateAccessGroupsRequest(
        accessGroupRequestMap: Map<String, List<String>>,
        selectedOrgs: Set<String>,
        allAccessGroups: List<AccessGroup>,
        userIsInternal: Boolean,
        callingUser: LdapUser,
        callingUserRoles: MemberOfToDeltaRolesMapper.Roles
    ) {
        validateAccessGroupRequest(
            accessGroupRequestMap,
            allAccessGroups,
            selectedOrgs,
            userIsInternal
        )
        validateOrganisationRequest(callingUser, callingUserRoles, selectedOrgs)
    }

    private suspend fun validateOrganisationRequest(
        callingUser: LdapUser,
        callingUserRoles: MemberOfToDeltaRolesMapper.Roles,
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
            if (!callingUserRoles.organisations.any { it.code == org }) {
                throw ApiError(
                    HttpStatusCode.BadRequest,
                    "user_not_member_of_selected_organisation",
                    "Organisation $org selected, but user is not a member of that organisation",
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
        val allAccessGroupsMap = allAccessGroups.associateBy { it.prefixedName }

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
                logger.info(
                        "Adding user {} to access group {}",
                        userToAdd.cn,
                    getGroupOrgADName(action.accessGroupName, action.organisationCode)
                    )
                groupService.addUserToGroup(
                    userToAdd.cn,
                    userToAdd.dn,
                    getGroupOrgADName(action.accessGroupName, action.organisationCode),
                    call,
                    adminSession
                )
            } else if (action is RemoveAccessGroupAction || action is RemoveAccessGroupOrganisationAction) {
                logger.info(
                        "Removing user {} from access group {}",
                        userToAdd.cn,
                    getGroupOrgADName(action.accessGroupName, action.organisationCode)
                    )
                groupService.removeUserFromGroup(
                    userToAdd.cn,
                    userToAdd.dn,
                    getGroupOrgADName(action.accessGroupName, action.organisationCode),
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

    private fun getGroupOrgADName(targetGroupName: String, targetOrganisationCode: String?) =
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
