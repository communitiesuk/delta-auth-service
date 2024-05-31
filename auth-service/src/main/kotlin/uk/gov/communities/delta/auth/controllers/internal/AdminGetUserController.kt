package uk.gov.communities.delta.auth.controllers.internal

import io.ktor.http.*
import io.ktor.server.application.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import org.slf4j.LoggerFactory
import uk.gov.communities.delta.auth.plugins.NoUserException
import uk.gov.communities.delta.auth.services.DeltaSystemRole
import uk.gov.communities.delta.auth.services.LdapUserWithRoles
import uk.gov.communities.delta.auth.services.UserGUIDMapService
import uk.gov.communities.delta.auth.services.UserLookupService
import uk.gov.communities.delta.auth.utils.getUserGUIDFromCallParameters

class AdminGetUserController(
    private val userLookupService: UserLookupService,
    private val userGUIDMapService: UserGUIDMapService,
) : AdminUserController(userLookupService) {

    private val logger = LoggerFactory.getLogger(javaClass)

    fun route(route: Route) {
        route.get { getUser(call) }
    }

    private suspend fun getUser(call: ApplicationCall) {
        getSessionIfUserHasPermittedRole(
            arrayOf(DeltaSystemRole.ADMIN, DeltaSystemRole.READ_ONLY_ADMIN), call
        )

        val userWithRoles: LdapUserWithRoles
        try {
            val userGUID = getUserGUIDFromCallParameters(
                call.request.queryParameters,
                userGUIDMapService,
                "An error occurred when getting user details",
                "get_user"
            )
            userWithRoles = userLookupService.lookupUserByGUIDAndLoadRoles(userGUID)
        } catch (e: NoUserException) {
            logger.warn(e.errorDescription)
            return call.respond(HttpStatusCode.NotFound, "User not found")
        }
        call.respond(userWithRoles)
    }
}
