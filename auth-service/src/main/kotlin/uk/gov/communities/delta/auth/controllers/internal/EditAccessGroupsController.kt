package uk.gov.communities.delta.auth.controllers.internal

import io.ktor.http.*
import io.ktor.server.application.*
import io.ktor.server.auth.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
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

    // This endpoint takes a map of access groups or organisations and a list of organisations. The map should contain all
    // access groups the user could potentially assign themselves to. Groups the user has selected should contain a list of
    // associated organisations, groups the user has not selected should contain an empty list. The list of organisations
    // should contain the organisations the user has chosen to be part of from the organisations available to them.
    private suspend fun updateUserAccessGroups(call: ApplicationCall) {
        val session = call.principal<OAuthSession>()!!
        val callingUser = userLookupService.lookupUserByCn(session.userCn)
        logger.atInfo().log("Updating access groups for user {}", session.userCn)
        val userIsInternal = callingUser.isInternal()
        val allAccessGroups = accessGroupsService.getAllAccessGroups()

        val requestBodyObject = call.receive<DeltaUserAccessGroups>()
        val selectedOrgs = requestBodyObject.userSelectedOrgs.toSet()
        val accessGroupsRequestMap = stripDatamartPrefixFromKeys(requestBodyObject.accessGroupsRequest)
        val accessGroupsRequested = accessGroupsRequestMap.filter { m -> m.value.isNotEmpty() }

        validateRequest(
            accessGroupsRequested,
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

        val accessGroupActions = generateAccessGroupActions(accessGroupsRequestMap, currentAccessGroups, selectedOrgs)

        executeAccessGroupActions(accessGroupActions, session, callingUser, call)

        return call.respond(mapOf("message" to "Access groups have been updated. Any changes to your roles or access groups will take effect the next time you log in."))
    }

    private suspend fun validateRequest(
        accessGroupsRequested: Map<String, List<String>>,
        selectedOrgs: Set<String>,
        allAccessGroups: List<AccessGroup>,
        userIsInternal: Boolean,
        callingUser: LdapUser
    ) {
        validateAccessGroupRequest(
            accessGroupsRequested,
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
        val userDomainOrgs =
            if (callingUser.email == null) listOf() else organisationService.findAllByDomain(callingUser.email)
                .map { it.code }
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
                    HttpStatusCode.Forbidden,
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
        session: OAuthSession,
        callingUser: LdapUser,
        call: ApplicationCall
    ) {
        for (action in accessGroupActions) {
            if (action is AddAccessGroupAction || action is AddAccessGroupOrganisationAction) {
                logger.atInfo()
                    .log("Adding user {} to access group {}", session.userCn, action.getActiveDirectoryString())
                groupService.addUserToGroup(
                    callingUser.cn,
                    callingUser.dn,
                    action.getActiveDirectoryString(),
                    call,
                    null
                )
            } else if (action is RemoveAccessGroupAction || action is RemoveAccessGroupOrganisationAction) {
                logger.atInfo()
                    .log("Removing user {} from access group {}", session.userCn, action.getActiveDirectoryString())
                groupService.removeUserFromGroup(
                    callingUser.cn,
                    callingUser.dn,
                    action.getActiveDirectoryString(),
                    call,
                    null
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
        fun getActiveDirectoryString() = LDAPConfig.DATAMART_DELTA_PREFIX + accessGroupName +
                if (organisationCode == null) "" else "-$organisationCode"
    }

    open class AddAccessGroupOrganisationAction(accessGroupName: String, organisationCode: String?) :
        AccessGroupAction(accessGroupName, organisationCode) {
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other !is AddAccessGroupOrganisationAction) return false

            return this.accessGroupName == other.accessGroupName && this.organisationCode == other.organisationCode
        }

        override fun hashCode(): Int {
            return javaClass.hashCode()
        }
    }

    class AddAccessGroupAction(accessGroupName: String) :
        AddAccessGroupOrganisationAction(accessGroupName, null)

    open class RemoveAccessGroupOrganisationAction(accessGroupName: String, organisationCode: String?) :
        AccessGroupAction(accessGroupName, organisationCode) {
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other !is RemoveAccessGroupOrganisationAction) return false

            return this.accessGroupName == other.accessGroupName && this.organisationCode == other.organisationCode
        }

        override fun hashCode(): Int {
            return javaClass.hashCode()
        }
    }

    class RemoveAccessGroupAction(accessGroupName: String) :
        RemoveAccessGroupOrganisationAction(accessGroupName, null)

    @Serializable
    data class DeltaUserAccessGroups(
        val accessGroupsRequest: Map<String, List<String>>,
        val userSelectedOrgs: List<String>,
    )
}
