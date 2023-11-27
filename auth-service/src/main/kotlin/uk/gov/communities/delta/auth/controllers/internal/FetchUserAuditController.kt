package uk.gov.communities.delta.auth.controllers.internal

import io.ktor.http.*
import io.ktor.server.application.*
import io.ktor.server.auth.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import io.ktor.server.util.*
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import org.slf4j.LoggerFactory
import uk.gov.communities.delta.auth.config.LDAPConfig.Companion.DATAMART_DELTA_PREFIX
import uk.gov.communities.delta.auth.repositories.LdapUser
import uk.gov.communities.delta.auth.services.OAuthSession
import uk.gov.communities.delta.auth.services.UserAuditService
import uk.gov.communities.delta.auth.services.UserLookupService
import uk.gov.communities.delta.auth.services.withSession

class FetchUserAuditController(
    private val userLookupService: UserLookupService,
    private val userAuditService: UserAuditService,
) {
    private val logger = LoggerFactory.getLogger(javaClass)

    fun route(route: Route) {
        route.get { getUserAudit(call) }
    }

    private suspend fun getUserAudit(call: ApplicationCall) {
        val session = call.principal<OAuthSession>()!!
        val callingUser = userLookupService.lookupUserByCn(session.userCn)
        val userCNParam = call.parameters.getOrFail("cn")

        if (!userHasPermissionToReadAuditTrail(callingUser, userCNParam)) {
            return call.respondUnauthorised(session, userCNParam)
        }

        logger.atInfo().withSession(session).log("Audit trail requested for {}", userCNParam)
        val audit = userAuditService.getAuditForUser(userCNParam)
        return call.respond(audit.map {
            JsonObject(
                mapOf(
                    "action" to JsonPrimitive(it.action.action),
                    "timestamp" to JsonPrimitive(it.timestamp.toInstant().toString()),
                    "userCN" to JsonPrimitive(it.userCn),
                    "editingUserCN" to JsonPrimitive(it.editingUserCn),
                    "requestId" to JsonPrimitive(it.requestId),
                    "actionData" to it.actionData,
                )
            )
        })
    }

    private val viewAuditAdminGroupCNs = listOf("admin", "read-only-admin").map { DATAMART_DELTA_PREFIX + it }

    private fun userHasPermissionToReadAuditTrail(callingUser: LdapUser, auditTrailOfUserCN: String): Boolean {
        if (callingUser.cn == auditTrailOfUserCN) return true // Everyone can see their own audit history

        return callingUser.memberOfCNs.any { viewAuditAdminGroupCNs.contains(it) }
    }

    private suspend fun ApplicationCall.respondUnauthorised(session: OAuthSession, userCNParam: String) {
        logger.atWarn().withSession(session)
            .log("User does not have permission to read audit log for {}", userCNParam)
        respond(
            HttpStatusCode.Forbidden,
            mapOf(
                "error" to "forbidden",
                "error_description" to "User does not have permission to read audit log for '$userCNParam'"
            )
        )
    }
}
