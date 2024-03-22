package uk.gov.communities.delta.auth.controllers.internal

import io.ktor.http.*
import io.ktor.server.application.*
import io.ktor.server.auth.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import kotlinx.serialization.Serializable
import org.slf4j.LoggerFactory
import uk.gov.communities.delta.auth.plugins.ApiError
import uk.gov.communities.delta.auth.services.OAuthSession
import uk.gov.communities.delta.auth.services.UserLookupService
import uk.gov.communities.delta.auth.services.UserService

class EditUsernameController(
    private val userLookupService: UserLookupService,
    private val userService: UserService,
) {

    private val logger = LoggerFactory.getLogger(javaClass)

    fun route(route: Route) {
        route.post { updateUsername(call) }
    }

    private suspend fun updateUsername(call: ApplicationCall) {
        val session = call.principal<OAuthSession>()!!
        val callingUser = userLookupService.lookupUserByCn(session.userCn)
        logger.atInfo().log("Updating organisations for user {}", session.userCn)

        val requestedUsername = call.receive<DeltaUsername>().username

        validateUsername(requestedUsername)

        userService.updateUsername(callingUser, requestedUsername, null, call)
        return call.respond(mapOf("message" to "Username has been updated."))
    }

    private fun validateUsername(requestedUsername: String) {
        if (requestedUsername.isBlank()) {
            throw ApiError(
                HttpStatusCode.Forbidden,
                "empty_username",
                "Username cannot be blank"
            )
        }
    }

    @Serializable
    data class DeltaUsername(
        val username: String,
    )
}
