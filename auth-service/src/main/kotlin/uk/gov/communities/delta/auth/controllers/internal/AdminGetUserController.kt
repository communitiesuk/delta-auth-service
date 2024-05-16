package uk.gov.communities.delta.auth.controllers.internal

import io.ktor.server.application.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import org.slf4j.LoggerFactory
import uk.gov.communities.delta.auth.services.DeltaSystemRole
import uk.gov.communities.delta.auth.services.UserLookupService
import uk.gov.communities.delta.auth.utils.getUserFromCallParameters
import uk.gov.communities.delta.auth.utils.getUserGUIDFromCallParameters

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

        // TODO DT-1022 - make this get userGUID instead
        val user = getUserFromCallParameters(
            call.request.queryParameters,
            userLookupService,
            "An error occurred when getting user details",
            "get_user"
        )
        logger.atInfo().log("Getting info for user ${user.getUUID()}")
//        val userWithRoles: LdapUserWithRoles
//        try { // TODO DT-1022 - add the try catch back in and change back to lookupUserByGUIDAndLoadRoles
        val userWithRoles = userLookupService.loadUserRoles(user)
//        } catch (e: LdapRepository.NoUserException) {
//            logger.warn("No user found with GUID $userGUID")
//            return call.respond(HttpStatusCode.NotFound, "User not found")
//        }
        call.respond(userWithRoles)
    }
}
