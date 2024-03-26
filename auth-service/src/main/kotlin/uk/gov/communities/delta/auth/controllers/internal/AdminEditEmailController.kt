package uk.gov.communities.delta.auth.controllers.internal

import io.ktor.http.*
import io.ktor.server.application.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import kotlinx.serialization.Serializable
import org.slf4j.LoggerFactory
import uk.gov.communities.delta.auth.plugins.ApiError
import uk.gov.communities.delta.auth.services.DeltaSystemRole
import uk.gov.communities.delta.auth.services.UserLookupService
import uk.gov.communities.delta.auth.services.UserService

class AdminEditEmailController(
    private val userLookupService: UserLookupService,
    private val userService: UserService,
) : AdminUserController(userLookupService) {

    private val logger = LoggerFactory.getLogger(javaClass)

    fun route(route: Route) {
        route.post { updateEmail(call) }
    }

    private suspend fun updateEmail(call: ApplicationCall) {
        val session = getSessionIfUserHasPermittedRole(
            arrayOf(DeltaSystemRole.ADMIN), call
        )
        val requestData = call.receive<DeltaEmailChangeRequest>()
        val requestedEmail = requestData.newEmail

        val userToEdit = userLookupService.lookupUserByCn(requestData.userToEditCn)

        logger.atInfo().log("Updating email and username for user {}", userToEdit.cn)

        validateEmail(requestedEmail)

        userService.updateEmail(userToEdit, requestedEmail, session, call)
        return call.respond(mapOf("message" to "Username has been updated."))
    }

    private fun validateEmail(requestedUsername: String) {
        if (requestedUsername.isBlank()) {
            throw ApiError(
                HttpStatusCode.Forbidden,
                "empty_username",
                "Username cannot be blank"
            )
        }
    }

    @Serializable
    data class DeltaEmailChangeRequest(
        val userToEditCn: String,
        val newEmail: String,
    )
}
