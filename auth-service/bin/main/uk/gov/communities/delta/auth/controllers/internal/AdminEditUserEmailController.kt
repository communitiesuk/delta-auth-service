package uk.gov.communities.delta.auth.controllers.internal

import io.ktor.http.*
import io.ktor.server.application.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import org.slf4j.LoggerFactory
import uk.gov.communities.delta.auth.plugins.ApiError
import uk.gov.communities.delta.auth.services.DeltaSystemRole
import uk.gov.communities.delta.auth.services.UserGUIDMapService
import uk.gov.communities.delta.auth.services.UserLookupService
import uk.gov.communities.delta.auth.services.UserService
import uk.gov.communities.delta.auth.utils.EmailAddressChecker

class AdminEditUserEmailController(
    private val userLookupService: UserLookupService,
    private val userGUIDMapService: UserGUIDMapService,
    private val userService: UserService,
) : AdminUserController(userLookupService) {

    private val logger = LoggerFactory.getLogger(javaClass)
    private val emailAddressChecker = EmailAddressChecker()

    fun route(route: Route) {
        route.post { updateEmail(call) }
    }

    private suspend fun updateEmail(call: ApplicationCall) {
        val session = getSessionIfUserHasPermittedRole(
            arrayOf(DeltaSystemRole.ADMIN), call
        )
        val requestData = call.receive<DeltaEmailChangeRequest>()
        val requestedEmail = requestData.newEmail

        // TODO DT-1022 - get GUID from request directly
        val userToEditGUID = userGUIDMapService.getGUIDFromCN(requestData.userToEditCn)
        val userToEdit = userLookupService.lookupUserByGUID(userToEditGUID)

        validateEmail(requestedEmail)
        logger.atInfo().addKeyValue("oldUserEmail", userToEdit.email)
            .addKeyValue("oldUserCN", userToEdit.cn)
            .addKeyValue("newUserEmail", requestedEmail)
            .log("Request to update email and username for user")

        userService.updateEmail(userToEdit, requestedEmail, session, call)
        return call.respond(mapOf("message" to "Username has been updated."))
    }

    private fun validateEmail(requestedUsername: String) {
        if (requestedUsername.isBlank()) {
            throw ApiError(
                HttpStatusCode.BadRequest,
                "empty_username",
                "Username cannot be blank"
            )
        }

        if (!emailAddressChecker.hasValidFormat(requestedUsername)) {
            throw ApiError(
                HttpStatusCode.BadRequest,
                "invalid_username",
                "Username must be a valid email"
            )
        }
    }

    @Serializable
    data class DeltaEmailChangeRequest(
        @SerialName("userToEditCn") val userToEditCn: String,
        @SerialName("newEmail") val newEmail: String,
    )
}
