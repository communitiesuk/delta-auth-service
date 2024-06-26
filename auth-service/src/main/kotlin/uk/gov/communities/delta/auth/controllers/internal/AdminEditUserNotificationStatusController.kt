package uk.gov.communities.delta.auth.controllers.internal

import io.ktor.server.application.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import kotlinx.serialization.Serializable
import org.slf4j.LoggerFactory
import uk.gov.communities.delta.auth.services.DeltaSystemRole
import uk.gov.communities.delta.auth.services.UserGUIDMapService
import uk.gov.communities.delta.auth.services.UserLookupService
import uk.gov.communities.delta.auth.services.UserService

class AdminEditUserNotificationStatusController(
    private val userLookupService: UserLookupService,
    private val userGUIDMapService: UserGUIDMapService,
    private val userService: UserService,
) : AdminUserController(userLookupService) {

    private val logger = LoggerFactory.getLogger(javaClass)

    fun route(route: Route) {
        route.post { updateUserNotifications(call) }
    }

    private suspend fun updateUserNotifications(call: ApplicationCall) {
        val session = getSessionIfUserHasPermittedRole(
            arrayOf(DeltaSystemRole.ADMIN, DeltaSystemRole.READ_ONLY_ADMIN), call
        )

        val requestData = call.receive<DeltaChangeNotificationStatusRequest>()

        val userToEditGUID = userGUIDMapService.getGUIDFromCN(requestData.userToEditCn)
        val userToEdit = userLookupService.lookupUserByGUID(userToEditGUID)
        logger.atInfo().log(
            "Updating notification status for user {} to {}",
            userToEdit.getGUID(),
            requestData.enableNotifications
        )

        userService.updateNotificationStatus(userToEdit, requestData.enableNotifications, session, call)
        return call.respond(mapOf("message" to "Notification status has been updated."))
    }

    @Serializable
    data class DeltaChangeNotificationStatusRequest(
        val userToEditCn: String,
        val enableNotifications: Boolean,
    )
}
