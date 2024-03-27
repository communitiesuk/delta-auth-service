package uk.gov.communities.delta.auth.controllers.internal

import io.ktor.server.application.*
import io.ktor.server.auth.*
import io.ktor.server.request.*
import io.ktor.server.routing.*
import kotlinx.serialization.Serializable
import org.slf4j.LoggerFactory
import uk.gov.communities.delta.auth.repositories.LdapUser
import uk.gov.communities.delta.auth.services.OAuthSession
import uk.gov.communities.delta.auth.services.UserLookupService
import uk.gov.communities.delta.auth.services.UserService
import javax.naming.directory.BasicAttribute
import javax.naming.directory.DirContext
import javax.naming.directory.ModificationItem

class EditUserDetailsController(
    val userLookupService: UserLookupService,
    val userService: UserService,
) {
    private val logger = LoggerFactory.getLogger(javaClass)

    fun route(route: Route) {
        route.post { updateUserDetails(call) }
    }

    private suspend fun updateUserDetails(call: ApplicationCall) {
        val session = call.principal<OAuthSession>()!!
        val callingUser = userLookupService.lookupUserByCn(session.userCn)
        logger.atInfo().log("Updating details for user {}", session.userCn)

        // TODO 694 do we want not to receive this whole object? only a few things are listed as updatable
        val updatedDeltaUserDetails = call.receive<DeltaUserDetailsRequest>()

        val modifications = getModifications(callingUser, updatedDeltaUserDetails)

        userService.updateUser(callingUser, modifications, null, call)
    }

    // TODO 694 in this and the below there is duplicated code from the admin edit user controller
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
