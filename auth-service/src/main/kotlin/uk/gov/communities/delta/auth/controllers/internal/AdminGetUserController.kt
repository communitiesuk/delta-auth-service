package uk.gov.communities.delta.auth.controllers.internal

import io.ktor.http.*
import io.ktor.server.application.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import org.slf4j.LoggerFactory
import uk.gov.communities.delta.auth.services.DeltaSystemRole
import uk.gov.communities.delta.auth.services.LdapUserWithRoles
import uk.gov.communities.delta.auth.services.UserLookupService
import javax.naming.NameNotFoundException

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

        val cn = call.request.queryParameters["userCn"]!!
        logger.atInfo().log("Getting info for user $cn")
        val user: LdapUserWithRoles
        try {
            user = userLookupService.lookupUserByCNAndLoadRoles(cn)
        } catch (e: NameNotFoundException) {
            logger.warn("User not found $cn")
            return call.respond(HttpStatusCode.NotFound, "User not found")
        }
        call.respond(LdapUserWithRoles(user.user, user.roles))
    }
}
