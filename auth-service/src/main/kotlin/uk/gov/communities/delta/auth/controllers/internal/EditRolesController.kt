package uk.gov.communities.delta.auth.controllers.internal

import io.ktor.server.application.*
import io.ktor.server.auth.*
import io.ktor.server.request.*
import io.ktor.server.routing.*
import org.slf4j.LoggerFactory
import uk.gov.communities.delta.auth.services.GroupService
import uk.gov.communities.delta.auth.services.OAuthSession
import uk.gov.communities.delta.auth.services.UserLookupService

class EditRolesController(
    private val userLookupService: UserLookupService,
    private val groupService: GroupService,) {

    private val logger = LoggerFactory.getLogger(javaClass)

    fun route(route: Route) {
        route.post { editUserRoles(call) }
    }

    private suspend fun editUserRoles(call: ApplicationCall) {

        // rather than checking admin, work out if they are internal or external user because they get different roles
        val session = call.principal<OAuthSession>()!!
        val callingUser = userLookupService.lookupUserByCn(session.userCn)
        // internal = part of the 'datamart-delta-dclg' group in AD
        val userInternal = true

        // kotlin json (see UserService.DeltaUserDetails)
        val ff = call.receive<String>()

    }
}