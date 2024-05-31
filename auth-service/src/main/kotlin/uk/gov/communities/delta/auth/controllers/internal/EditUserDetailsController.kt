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
import uk.gov.communities.delta.auth.plugins.ApiError
import uk.gov.communities.delta.auth.repositories.LdapUser
import uk.gov.communities.delta.auth.services.OAuthSession
import uk.gov.communities.delta.auth.services.UserLookupService
import uk.gov.communities.delta.auth.services.UserService
import uk.gov.communities.delta.auth.utils.getModificationItem
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
        val callingUser = userLookupService.lookupCurrentUser(session)
        logger.atInfo().log("Updating details for user {}", session.userCn)

        val updatedDeltaUserDetails = call.receive<DeltaUserMyDetails>()

        if (!updatedDeltaUserDetails.telephone.isNullOrEmpty() && !updatedDeltaUserDetails.telephone.matches(Regex("^[0-9]+\$"))) {
            throw ApiError(
                HttpStatusCode.Forbidden,
                "non_numeric_telephone_number",
                "Telephone number must contain only numeric characters 0-9",
                "Telephone number must contain only numeric characters 0-9",
            )
        }

        val modifications = getModifications(callingUser, updatedDeltaUserDetails)

        userService.updateUser(callingUser, modifications, null, userLookupService, call)

        return call.respond(mapOf("message" to "Details have been updated."))
    }

    private fun getModifications(
        currentUser: LdapUser,
        newUser:DeltaUserMyDetails
    ): Array<ModificationItem> {
        var modifications = arrayOf<ModificationItem>()

        getModificationItem("sn", currentUser.lastName, newUser.lastName)?.let { modifications += it }
        getModificationItem("givenName", currentUser.firstName, newUser.firstName)?.let { modifications += it }
        getModificationItem("telephoneNumber", currentUser.telephone, newUser.telephone)?.let { modifications += it }
        getModificationItem("title", currentUser.positionInOrganisation, newUser.position)?.let { modifications += it }

        return modifications
    }

    @Serializable
    data class DeltaUserMyDetails(
        @SerialName("lastName") val lastName: String,
        @SerialName("firstName") val firstName: String,
        @SerialName("telephone") val telephone: String? = null,
        @SerialName("position") val position: String? = null,
    )
}
