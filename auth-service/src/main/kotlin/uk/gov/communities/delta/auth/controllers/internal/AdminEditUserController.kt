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
import javax.naming.NameNotFoundException
import javax.naming.directory.BasicAttribute
import javax.naming.directory.DirContext
import javax.naming.directory.ModificationItem

class AdminEditUserController(
    private val userLookupService: UserLookupService,
    private val userService: UserService,
    private val groupService: GroupService,
    private val emailService: EmailService,
) : AdminUserController(userLookupService) {

    private val logger = LoggerFactory.getLogger(javaClass)

    fun route(route: Route) {
        route.post { editUser(call) }
    }

    private suspend fun editUser(call: ApplicationCall) {

        val session = getSessionIfUserHasPermittedRole(
            arrayOf(
                DeltaConfig.DATAMART_DELTA_ADMIN,
            ), call
        )

        val cn = call.request.queryParameters["userCn"]!!
        logger.atInfo().log("Updating user $cn")
        val currentUser: LdapUser
        try {
            currentUser = userLookupService.lookupUserByCn(cn)
        } catch (e: NameNotFoundException) {
            throw ApiError(
                HttpStatusCode.BadRequest,
                "no_existing_user",
                "Attempting to update a user that doesn't exist",
            )
        }

        val recipient: LdapUser
        try {
            recipient = userLookupService.lookupUserByCn(session.userCn)
        } catch (e: NameNotFoundException) {
            throw ApiError(
                HttpStatusCode.BadRequest,
                "no_existing_user",
                "Attempting to retrieve a user that doesn't exist",
            )
        }

        val updatedDeltaUserDetails = call.receive<UserService.DeltaUserDetails>()

        if (updatedDeltaUserDetails.id.replace("@", "!") != cn) throw ApiError(
            HttpStatusCode.BadRequest,
            "username_changed",
            "Username has been changed"
        )

        val modifications = getModifications(currentUser, updatedDeltaUserDetails)
        val updatedUserGroups = updatedDeltaUserDetails.getGroups()
        val groupsToAddToUser = updatedUserGroups.filter { it !in currentUser.memberOfCNs && editableGroup(it) }
        val groupsToRemoveFromUser = currentUser.memberOfCNs.filter { it !in updatedUserGroups && editableGroup(it) }

        if (modifications.isEmpty() && groupsToAddToUser.isEmpty() && groupsToRemoveFromUser.isEmpty())
            return call.respond(mapOf("message" to "No changes were made to the user"))

        if (modifications.isNotEmpty()) userService.updateUser(currentUser, modifications, session, call)

        groupsToAddToUser.forEach {
            groupService.addUserToGroup(currentUser.cn, currentUser.dn, it, call, session)
            if (currentUser.email?.contains("levellingup.gov.uk") == true)
            {
                emailService.sendDLUHCUserAddedToUserGroupEmail(currentUser, recipient, it)
            }
        }
        groupsToRemoveFromUser.forEach {
            groupService.removeUserFromGroup(currentUser.cn, currentUser.dn, it, call, session)
        }

        logger.atInfo().log("User $cn successfully updated")

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
        newUser: UserService.DeltaUserDetails
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

    private fun getModificationItem(
        parameterName: String,
        currentValue: String?,
        newValue: String?
    ): ModificationItem? {
        return if (!currentValue.equals(newValue)) {
            if (currentValue.isNullOrEmpty())
                if (newValue.isNullOrEmpty()) null
                else ModificationItem(DirContext.ADD_ATTRIBUTE, BasicAttribute(parameterName, newValue))
            else if (newValue.isNullOrEmpty())
                ModificationItem(DirContext.REMOVE_ATTRIBUTE, BasicAttribute(parameterName))
            else
                ModificationItem(DirContext.REPLACE_ATTRIBUTE, BasicAttribute(parameterName, newValue))
        } else null
    }

}