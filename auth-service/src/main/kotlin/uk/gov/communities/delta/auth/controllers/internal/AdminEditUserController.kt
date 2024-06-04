package uk.gov.communities.delta.auth.controllers.internal

import io.ktor.http.*
import io.ktor.server.application.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import org.slf4j.LoggerFactory
import uk.gov.communities.delta.auth.config.DeltaConfig
import uk.gov.communities.delta.auth.config.LDAPConfig
import uk.gov.communities.delta.auth.plugins.ApiError
import uk.gov.communities.delta.auth.repositories.LdapUser
import uk.gov.communities.delta.auth.services.*
import uk.gov.communities.delta.auth.utils.getModificationItem
import uk.gov.communities.delta.auth.utils.getUserGUIDFromCallParameters
import javax.naming.directory.ModificationItem

class AdminEditUserController(
    private val userLookupService: UserLookupService,
    private val userGUIDMapService: UserGUIDMapService,
    private val userService: UserService,
    private val groupService: GroupService,
    private val deltaUserPermissionsRequestMapper: DeltaUserPermissionsRequestMapper,
    private val accessGroupDCLGMembershipUpdateEmailService: AccessGroupDCLGMembershipUpdateEmailService,
) : AdminUserController(userLookupService) {

    private val logger = LoggerFactory.getLogger(javaClass)

    fun route(route: Route) {
        route.post { editUser(call) }
    }

    private suspend fun editUser(call: ApplicationCall) {

        val (session, callingUser) = getSessionAndUserIfUserHasPermittedRole(
            arrayOf(DeltaSystemRole.ADMIN), call
        )

        val userToUpdateGUID = getUserGUIDFromCallParameters(
            call.request.queryParameters,
            userGUIDMapService,
            "Something went wrong, please try again",
            "update_user_as_admin"
        )
        val (userToUpdate, userToUpdateRoles) = userLookupService.lookupUserByGUIDAndLoadRoles(userToUpdateGUID)

        logger.atInfo().log("Updating user with GUID ${userToUpdate.getGUID()}")
        val updatedDeltaUserDetailsRequest = call.receive<DeltaUserDetailsRequest>()

        if (LDAPConfig.emailToCN(updatedDeltaUserDetailsRequest.id) != userToUpdate.cn) throw ApiError(
            HttpStatusCode.BadRequest,
            "username_changed",
            "Username has been changed"
        )

        val updatedPermissions = try {
            deltaUserPermissionsRequestMapper.deltaRequestToUserPermissions(updatedDeltaUserDetailsRequest)
        } catch (e: DeltaUserPermissions.Companion.BadInput) {
            throw ApiError(
                HttpStatusCode.BadRequest,
                "bad_request",
                e.message!!,
                "Requested permissions are invalid: ${e.message}"
            )
        }
        val modifications = getModifications(userToUpdate, updatedDeltaUserDetailsRequest)
        val updatedUserGroups = updatedPermissions.getADGroupCNs()
        val groupsToAddToUser = updatedUserGroups.filter { it !in userToUpdate.memberOfCNs && editableGroup(it) }
        val groupsToRemoveFromUser = userToUpdate.memberOfCNs.filter { it !in updatedUserGroups && editableGroup(it) }

        if (modifications.isEmpty() && groupsToAddToUser.isEmpty() && groupsToRemoveFromUser.isEmpty())
            return call.respond(mapOf("message" to "No changes were made to the user"))

        if (modifications.isNotEmpty()) userService.updateUser(userToUpdate, modifications, session, call)

        groupsToAddToUser.forEach { groupService.addUserToGroup(userToUpdate, it, call, session) }
        groupsToRemoveFromUser.forEach { groupService.removeUserFromGroup(userToUpdate, it, call, session) }

        logger.atInfo().log("User ${userToUpdate.getGUID()} successfully updated")

        accessGroupDCLGMembershipUpdateEmailService.sendNotificationEmailsForChangeToUserAccessGroups(
            AccessGroupDCLGMembershipUpdateEmailService.UpdatedUser(userToUpdate),
            callingUser,
            userToUpdateRoles.accessGroups,
            updatedPermissions.accessGroups,
        )

        return call.respond(mapOf("message" to "User profile has been updated. Any changes to their roles or access groups will take effect the next time they log in."))
    }

    private fun editableGroup(group: String): Boolean {
        return if (!group.startsWith(LDAPConfig.DATAMART_DELTA_PREFIX)) false
        else if (group.startsWith(DeltaConfig.DATAMART_DELTA_ADMIN)) false
        else if (group == DeltaConfig.DATAMART_DELTA_USER) false
        else if (DELTA_EXTERNAL_ROLES.any{group.contains(it)}) false
        else true
    }

    private fun getModifications(
        currentUser: LdapUser,
        newUser: DeltaUserDetailsRequest
    ): Array<ModificationItem> {
        var modifications = arrayOf<ModificationItem>()

        getModificationItem("sn", currentUser.lastName, newUser.lastName)?.let { modifications += it }
        getModificationItem("givenName", currentUser.firstName, newUser.firstName)?.let { modifications += it }
        getModificationItem("comment", currentUser.comment, newUser.comment)?.let { modifications += it }
        getModificationItem("telephoneNumber", currentUser.telephone, newUser.telephone)?.let { modifications += it }
        getModificationItem("mobile", currentUser.mobile, newUser.mobile)?.let { modifications += it }
        getModificationItem(
            "description",
            currentUser.reasonForAccess,
            newUser.reasonForAccess
        )?.let { modifications += it }
        getModificationItem("title", currentUser.positionInOrganisation, newUser.position)?.let { modifications += it }

        return modifications
    }

}
