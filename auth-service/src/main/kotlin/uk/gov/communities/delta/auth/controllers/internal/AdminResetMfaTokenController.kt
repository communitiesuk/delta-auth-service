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

class AdminResetMfaTokenController (
    private val userLookupService: UserLookupService,
    private val userGUIDMapService: UserGUIDMapService,
    private val userService: UserService,
) : AdminUserController(userLookupService) {

    private val logger = LoggerFactory.getLogger(javaClass)

    fun route(route: Route) {
        route.post { resetUserMfaToken(call) }
    }

    private suspend fun resetUserMfaToken(call: ApplicationCall) {
        val session = getSessionIfUserHasPermittedRole(
            arrayOf(DeltaSystemRole.ADMIN), call
        )

        val requestData = call.receive<DeltaResetMfaTokenRequest>()

        val userToEditGUID = userGUIDMapService.getGUIDFromCN(requestData.userToEditCn) // TODO DT-1022 - get GUID directly
        val userToEdit = userLookupService.lookupUserByGUID(userToEditGUID)
        logger.atInfo().log("Resetting MFA token for user {}", userToEdit.getGUID())

        if (userToEdit.deltaTOTPSecret.isNullOrEmpty()) {
            return call.respond(mapOf("message" to "User MFA token already reset."))
        }

        userService.resetMfaToken(userToEdit, session, call)
        return call.respond(mapOf("message" to "MFA token has been updated."))
    }

    @Serializable
    data class DeltaResetMfaTokenRequest(
        val userToEditCn: String,
    )
}
