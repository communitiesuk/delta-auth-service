package uk.gov.communities.delta.auth.controllers.internal

import io.ktor.http.*
import io.ktor.server.application.*
import io.ktor.server.auth.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import io.ktor.server.util.*
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import org.slf4j.LoggerFactory
import uk.gov.communities.delta.auth.config.LDAPConfig.Companion.DATAMART_DELTA_PREFIX
import uk.gov.communities.delta.auth.plugins.ApiError
import uk.gov.communities.delta.auth.repositories.LdapUser
import uk.gov.communities.delta.auth.repositories.UserAuditTrailRepo
import uk.gov.communities.delta.auth.services.OAuthSession
import uk.gov.communities.delta.auth.services.UserAuditService
import uk.gov.communities.delta.auth.services.UserLookupService
import uk.gov.communities.delta.auth.services.withSession
import uk.gov.communities.delta.auth.utils.csvRow

class FetchUserAuditController(
    private val userLookupService: UserLookupService,
    private val userAuditService: UserAuditService,
) {
    private val logger = LoggerFactory.getLogger(javaClass)
    private val defaultPageSize = 100

    fun route(route: Route) {
        route.get { call.getUserAuditJson() }
        route.get("/csv") { call.getUserAuditCSV() }
    }

    @Serializable
    data class UserAuditJsonResponse(val userAudit: List<JsonObject>, val totalRecords: Int)

    private suspend fun ApplicationCall.getUserAuditJson() {
        val session = principal<OAuthSession>()!!
        val page = (parameters["page"]?.toInt() ?: 1).apply {
            if (this < 1) throw ApiError(
                HttpStatusCode.BadRequest,
                "bad_request",
                "Page number must be positive"
            )
        }
        val pageSize = (parameters["pageSize"]?.toInt() ?: defaultPageSize).apply {
            if (this < 1) throw ApiError(
                HttpStatusCode.BadRequest,
                "bad_request",
                "Page size must be positive"
            )
        }
        val targetUserCn = parameters.getOrFail("cn")
        checkPermissions(session, targetUserCn)

        logger.atInfo().withSession(session).log("Audit trail page {} requested for {}", page, targetUserCn)
        val (audit, totalRecords) = userAuditService.getAuditForUserPaged(targetUserCn, page, pageSize)

        return respond(
            UserAuditJsonResponse(
                audit.map {
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
                },
                totalRecords
            )
        )
    }

    private suspend fun ApplicationCall.getUserAuditCSV() {
        val session = principal<OAuthSession>()!!
        val userCn = parameters.getOrFail("cn")
        checkPermissions(session, userCn)

        logger.atInfo().withSession(session).log("Audit trail page CSV requested for {}", userCn)

        val audit = userAuditService.getAuditForUser(userCn)
        val csvString = buildCSVFromAudit(audit)
        respondBytes(csvString.toByteArray(), ContentType.Text.CSV)
    }

    private fun buildCSVFromAudit(audit: List<UserAuditTrailRepo.UserAuditRow>): String {
        val extraCSVHeaders = audit.flatMap { it.actionData.keys }.distinct()
        val stringBuilder = StringBuilder()
        stringBuilder.csvRow(listOf("action", "timestamp", "userCN", "editingUserCN", "requestId") + extraCSVHeaders)

        for (auditRow in audit) {
            val csvRow = mutableListOf(
                auditRow.action.action,
                auditRow.timestamp.toInstant().toString(),
                auditRow.userCn,
                auditRow.editingUserCn ?: "",
                auditRow.requestId
            )
            extraCSVHeaders.forEach {
                when (val jsonElement = auditRow.actionData[it]) {
                    is JsonPrimitive -> csvRow.add(jsonElement.content)
                    else -> csvRow.add("")
                }
            }
            stringBuilder.csvRow(csvRow)
        }
        return stringBuilder.toString()
    }

    private suspend fun checkPermissions(session: OAuthSession, targetUserCn: String) {
        val callingUser = userLookupService.lookupUserByCn(session.userCn)

        if (!userHasPermissionToReadAuditTrail(callingUser, targetUserCn)) {
            logger.atWarn().withSession(session)
                .log("User does not have permission to read audit log for {}", targetUserCn)
            throw AccessDeniedError("User does not have permission to read audit log for $targetUserCn")
        }
    }

    private val viewAuditAdminGroupCNs = listOf("admin", "read-only-admin").map { DATAMART_DELTA_PREFIX + it }

    private fun userHasPermissionToReadAuditTrail(callingUser: LdapUser, auditTrailOfUserCN: String): Boolean {
        if (callingUser.cn == auditTrailOfUserCN) return true // Everyone can see their own audit history

        return callingUser.memberOfCNs.any { viewAuditAdminGroupCNs.contains(it) }
    }

    class AccessDeniedError(description: String) :
        ApiError(HttpStatusCode.Forbidden, "forbidden", description, description)
}
