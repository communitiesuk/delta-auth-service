package uk.gov.communities.delta.auth.controllers.internal

import io.ktor.http.*
import io.ktor.server.application.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.serialization.Serializable
import org.slf4j.LoggerFactory
import uk.gov.communities.delta.auth.config.DeltaConfig
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
    private val organisationService: OrganisationService,
    private val accessGroupsService: AccessGroupsService,
    private val memberOfToDeltaRolesMapperFactory: MemberOfToDeltaRolesMapperFactory,
) : AdminUserController(userLookupService) {

    // TODO - Notification Status, Enabled/Disabled, MFA - this ticket or next?

    private val logger = LoggerFactory.getLogger(javaClass)

    fun route(route: Route) {
        route.get { getUser(call) }
        route.post { editUser(call) }
    }

    private suspend fun getUser(call: ApplicationCall) {
        getSessionIfUserHasPermittedRole(
            arrayOf(
                DeltaConfig.DATAMART_DELTA_ADMIN,
                DeltaConfig.DATAMART_DELTA_READ_ONLY_ADMIN,
            ), call
        )

        val cn = call.request.queryParameters["userCn"]!!
        logger.atInfo().log("Getting info for user $cn")
        val user = userLookupService.lookupUserByCn(cn)
        coroutineScope {
            val allOrganisations = async { organisationService.findAllNamesAndCodes() }
            val allAccessGroups = async { accessGroupsService.getAllAccessGroups() }

            val roles = memberOfToDeltaRolesMapperFactory(
                user.cn, allOrganisations.await(), allAccessGroups.await()
            ).map(user.memberOfCNs)
            call.respond(UserWithRoles(user, roles))
        }

    }

    @Serializable
    data class UserWithRoles(val user: LdapUser, val roles: MemberOfToDeltaRolesMapper.Roles)

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

        val updatedDeltaUserDetails = call.receive<UserService.DeltaUserDetails>()

        if (updatedDeltaUserDetails.id.replace("@", "!") != cn) throw Exception("Username has been changed")

        val modifications = getModifications(currentUser, updatedDeltaUserDetails)
        val updatedUserGroups = updatedDeltaUserDetails.getGroups()
        val groupsToAddToUser = updatedUserGroups.filter { it !in currentUser.memberOfCNs }
        val groupsToRemoveFromUser = currentUser.memberOfCNs.filter { it !in updatedUserGroups }

        if (modifications.isEmpty() && groupsToAddToUser.isEmpty() && groupsToRemoveFromUser.isEmpty())
            return call.respond(mapOf("message" to "No changes were made to the user"))

        userService.updateUser(currentUser, modifications, session, call)
        groupsToAddToUser.forEach {
            groupService.addUserToGroup(currentUser.cn, currentUser.dn, it, call, session)
        }
        groupsToRemoveFromUser.forEach {
            groupService.removeUserFromGroup(currentUser.cn, currentUser.dn, it, call, session)
        }

        logger.atInfo().log("User $cn successfully updated")

        return call.respond(mapOf("message" to "User profile has been updated. Any changes to their roles or access groups will take effect the next time they log in."))
    }

    private fun getModifications(
        currentUser: LdapUser,
        newUser: UserService.DeltaUserDetails
    ): Array<ModificationItem> {
        var modifications = arrayOf<ModificationItem>()

        getModificationItem("sn", currentUser.lastName, newUser.lastName)?.let { modifications += it }
        getModificationItem("givenName", currentUser.firstName, newUser.firstName)?.let { modifications += it }
        getModificationItem("mail", currentUser.email, newUser.email)?.let { modifications += it }
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