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

    // This endpoint takes a list of access groups to add and to remove in the form of maps of the group name (with
    // delta prefix) and a list of organisations for that access group. Generation of the correct lists is performed in
    // Delta.
    private suspend fun updateUserAccessGroups(call: ApplicationCall) {
        val session = call.principal<OAuthSession>()!!
        val callingUser = userLookupService.lookupUserByCn(session.userCn)
        logger.atInfo().log("Updating access groups for user ${session.userCn}")
        val userInternal = callingUser.isInternal()

        val requestBodyObject = call.receive<DeltaUserAccessGroups>()
        val rawAccessGroupsRequestMap = requestBodyObject.accessGroupsRequest

        val accessGroupsRequestMap = stripDatamartPrefixFromKeys(rawAccessGroupsRequestMap)

        val accessGroupsRequested = accessGroupsRequestMap.filter { m -> m.value.isNotEmpty() }

        val allAccessGroups = accessGroupsService.getAllAccessGroups().associateBy { it.name }

        for (requestedAccessGroup in accessGroupsRequested) {
            val accessGroupData = allAccessGroups.getOrElse(requestedAccessGroup.key) {
                throw ApiError(
                    HttpStatusCode.Forbidden,
                    "inexistent_group",
                    "Attempted to assign a user an access group that does not exist: "
                            + requestedAccessGroup.key,
                )
            }

            if (userInternal && !accessGroupData.enableInternalUser) {
                throw ApiError(
                    HttpStatusCode.Forbidden,
                    "internal_user_non_internal_group",
                    "Attempted to assign an internal user a group not enabled for internal users: "
                            + requestedAccessGroup.key,
                )
            }

            if (!userInternal && !accessGroupData.enableOnlineRegistration) {
                throw ApiError(
                    HttpStatusCode.Forbidden,
                    "external_user_non_online_registration_group",
                    "Attempted to assign an external user a group not enabled for online registration: "
                            + requestedAccessGroup.key,
                )
            }
        }

        val mapperResult = memberOfToDeltaRolesMapperFactory(
            callingUser.cn, organisationService.findAllNamesAndCodes(), accessGroupsService.getAllAccessGroups()
        ).map(callingUser.memberOfCNs)

        val currentAccessGroups = mapperResult.accessGroups.associateBy({ it.name },
            { it.organisationIds })

        val accessGroupActions = mutableListOf<AccessGroupAction>()

        val selectedOrgs = requestBodyObject.userSelectedOrgs

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

        for (action in accessGroupActions) {
            if (action is AddAccessGroupAction || action is AddAccessGroupOrganisationAction) {
                logger.atInfo().log("Adding user ${session.userCn} to access group ${action.getActiveDirectoryString()}")
                groupService.addUserToGroup(
                    callingUser.cn,
                    callingUser.dn,
                    action.getActiveDirectoryString(),
                    call,
                    null
                )
            } else if (action is RemoveAccessGroupAction || action is RemoveAccessGroupOrganisationAction) {
                logger.atInfo().log("Removing user ${session.userCn} from access group ${action.getActiveDirectoryString()}")
                groupService.removeUserFromGroup(
                    callingUser.cn,
                    callingUser.dn,
                    action.getActiveDirectoryString(),
                    call,
                    null
                )
            }
        }

        return call.respond(mapOf("message" to "Access groups have been updated. Any changes to your roles or access groups will take effect the next time you log in."))
    }

    private fun stripDatamartPrefixFromKeys(prefixedMap: Map<String, List<String>>): Map<String, List<String>> {
        val newMap = mutableMapOf<String, List<String>>()
        for (entry in prefixedMap.entries) {
            newMap[entry.key.removePrefix(LDAPConfig.DATAMART_DELTA_PREFIX)] = entry.value
        }
        return newMap.toMap()
    }

    private sealed class AccessGroupAction(
        val accessGroupName: String,
        val organisationCode: String?,
    ) {
        fun getActiveDirectoryString() = LDAPConfig.DATAMART_DELTA_PREFIX + accessGroupName +
                if (organisationCode == null) "" else "-$organisationCode"
    }

    private class AddAccessGroupAction(accessGroupName: String) : AccessGroupAction(accessGroupName, null)
    private class AddAccessGroupOrganisationAction(accessGroupName: String, organisationCode: String?) :
        AccessGroupAction(accessGroupName, organisationCode)

    private class RemoveAccessGroupAction(accessGroupName: String) : AccessGroupAction(accessGroupName, null)
    private class RemoveAccessGroupOrganisationAction(accessGroupName: String, organisationCode: String?) :
        AccessGroupAction(accessGroupName, organisationCode)

    @Serializable
    data class DeltaUserAccessGroups(
        val accessGroupsRequest: Map<String, List<String>>,
        val userSelectedOrgs: List<String>,
    )
}
