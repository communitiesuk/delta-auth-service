package uk.gov.communities.delta.auth.controllers.internal

import io.ktor.http.*
import io.ktor.server.application.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import org.slf4j.LoggerFactory
import uk.gov.communities.delta.auth.plugins.ApiError
import uk.gov.communities.delta.auth.services.DeltaSystemRole
import uk.gov.communities.delta.auth.services.LdapUserWithRoles
import uk.gov.communities.delta.auth.services.UserLookupService
import uk.gov.communities.delta.auth.utils.getUserFromCallParameters

class AdminGetUserController(
    private val userLookupService: UserLookupService,
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
            val user = getUserFromCallParameters( // TODO DT-1022 - make this get userGUID instead
                call.request.queryParameters,
                userLookupService,
                "An error occurred when getting user details",
                "get_user"
            )
            userWithRoles = userLookupService.loadUserRoles(user) // TODO DT-1022 - change back to lookupUserByGUIDAndLoadRoles
        } catch (e: ApiError) {
            logger.warn(e.errorDescription)
            return call.respond(HttpStatusCode.NotFound, "User not found")
        }
        call.respond(userWithRoles)
    }
}
