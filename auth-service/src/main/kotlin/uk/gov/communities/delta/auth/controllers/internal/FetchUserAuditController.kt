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
import uk.gov.communities.delta.auth.plugins.NoUserException
import uk.gov.communities.delta.auth.repositories.LdapUser
import uk.gov.communities.delta.auth.repositories.UserAuditTrailRepo
import uk.gov.communities.delta.auth.services.OAuthSession
import uk.gov.communities.delta.auth.services.UserAuditService
import uk.gov.communities.delta.auth.services.UserGUIDMapService
import uk.gov.communities.delta.auth.services.UserLookupService
import uk.gov.communities.delta.auth.utils.csvRow
import uk.gov.communities.delta.auth.utils.getIdentifyingParameterOrEmpty
import uk.gov.communities.delta.auth.utils.getUserGUIDFromCallParameters
import java.time.Instant
import java.time.LocalDate
import java.time.ZoneId
import java.time.format.DateTimeFormatter
import java.time.format.DateTimeParseException
import java.time.temporal.ChronoUnit
import java.util.*

class FetchUserAuditController(
    private val userLookupService: UserLookupService,
    private val userGUIDMapService: UserGUIDMapService,
    private val userAuditService: UserAuditService,
) {
    private val logger = LoggerFactory.getLogger(javaClass)
    private val defaultPageSize = 100

    fun route(route: Route) {
        route.get { call.getUserAuditJson() }
        route.get("/csv") { call.getUserAuditCSV() }
        route.get("/all-csv") { call.getAllUsersAuditCSV() }
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
        val targetUserGUID = try {
            getUserGUIDFromCallParameters(
                parameters,
                userGUIDMapService,
                "Something went wrong, please try again",
                "get_audit"
            )
        } catch (e: NoUserException) {
            // If user isn't an admin throw AccessDeniedError to avoid confirming user existence
            if (userLookupService.lookupCurrentUser(session).memberOfCNs.any { viewAuditAdminGroupCNs.contains(it) })
                throw e
            else throw AuditAccessDeniedError(getIdentifyingParameterOrEmpty(parameters))//TODO DT-1022 - once receiving GUID just use that here
        }

        checkPermissions(session, targetUserGUID, getIdentifyingParameterOrEmpty(parameters))

        logger.atInfo().log("Audit trail page {} requested for {}", page, targetUserGUID)
        val (audit, totalRecords) = userAuditService.getAuditForUserPaged(targetUserGUID, page, pageSize)

        return respond(
            UserAuditJsonResponse(
                audit.map {
                    JsonObject(
                        mapOf(
                            "action" to JsonPrimitive(it.action.action),
                            "timestamp" to JsonPrimitive(it.timestamp.toInstant().toString()),
                            "userCN" to JsonPrimitive(it.userCN),
                            "editingUserCN" to JsonPrimitive(it.editingUserCN),
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
        val userGUID = try {
            getUserGUIDFromCallParameters(
            parameters,
            userGUIDMapService,
            "Something went wrong, please try again",
            "get_audit"
            )
        } catch (e: NoUserException) {
            // If user isn't an admin throw AccessDeniedError to avoid confirming user existence
            if (userLookupService.lookupCurrentUser(session).memberOfCNs.any { viewAuditAdminGroupCNs.contains(it) })
                throw e
            else throw AuditAccessDeniedError(getIdentifyingParameterOrEmpty(parameters))//TODO DT-1022 - once receiving GUID just use that here
        }

        checkPermissions(session, userGUID, getIdentifyingParameterOrEmpty(parameters))
        logger.atInfo().log("Audit trail CSV requested for user {}", userGUID)
        val audit = userAuditService.getAuditForUser(userGUID)
        val csvString = buildCSVFromAudit(audit)
        respondBytes(csvString.toByteArray(), ContentType.Text.CSV)
    }

    // CSV download of audited actions for all users between two dates
    // GET /auth-internal/bearer/user-audit/all-csv?fromDate=2024-01-01&toDate=2024-01-05
    // Dates range is inclusive, interpreted as Europe/London timezone
    private suspend fun ApplicationCall.getAllUsersAuditCSV() {
        val session = principal<OAuthSession>()!!
        val callingUser = userLookupService.lookupCurrentUser(session)
        if (!callingUser.memberOfCNs.any { viewAuditAdminGroupCNs.contains(it) }) {
            throw AccessDeniedError("User does not have permission to read all user audit log")
        }
        val fromDate = parameters.getDateParam("fromDate")
        val toDate = parameters.getDateParam("toDate").plus(1, ChronoUnit.DAYS)

        logger.atInfo().log("Audit trail CSV requested for all users from {} to {}", fromDate, toDate)

        val audit = userAuditService.getAuditForAllUsers(fromDate, toDate)
        val csvString = buildCSVFromAudit(audit)
        respondBytes(csvString.toByteArray(), ContentType.Text.CSV)
    }

    private fun Parameters.getDateParam(name: String): Instant {
        val date = this.getOrFail(name)
        try {
            return LocalDate.parse(date, DateTimeFormatter.ISO_LOCAL_DATE)
                .atStartOfDay(ZoneId.of("Europe/London"))
                .toInstant()
        } catch (ex: DateTimeParseException) {
            throw ApiError(
                HttpStatusCode.BadRequest,
                "bad_request",
                "Invalid date parameter '$name', expected format yyyy-MM-dd"
            )
        }
    }

    private fun buildCSVFromAudit(audit: List<UserAuditTrailRepo.UserAuditRow>): String {
        val extraCSVHeaders = audit.flatMap { it.actionData.keys }.distinct()
        val stringBuilder = StringBuilder()
        stringBuilder.csvRow(listOf("action", "timestamp", "userCN", "userGUID", "editingUserCN", "editingUserGUID", "requestId") + extraCSVHeaders)

        for (auditRow in audit) {
            val csvRow = mutableListOf(
                auditRow.action.action,
                auditRow.timestamp.toInstant().toString(),
                auditRow.userCN,
                auditRow.userGUID.toString(),
                auditRow.editingUserCN ?: "",
                auditRow.editingUserGUID?.toString()?:"",
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

    private suspend fun checkPermissions(session: OAuthSession, targetUserGUID: UUID, identifyingParameter: String) {
        val callingUser = userLookupService.lookupCurrentUser(session)

        if (!userHasPermissionToReadAuditTrail(callingUser, targetUserGUID)) {
            logger.atWarn()
                .log("User does not have permission to read audit log for {}", targetUserGUID)
            throw AuditAccessDeniedError(identifyingParameter) //TODO DT-1022 - once receiving GUID just use that here
        }
    }

    class AuditAccessDeniedError(identifyingParameter: String) :
        AccessDeniedError("User does not have permission to read audit log for $identifyingParameter")

    private val viewAuditAdminGroupCNs = listOf("admin", "read-only-admin").map { DATAMART_DELTA_PREFIX + it }

    private fun userHasPermissionToReadAuditTrail(callingUser: LdapUser, auditTrailOfUserGUID: UUID): Boolean {
        if (callingUser.getGUID() == auditTrailOfUserGUID) return true // Everyone can see their own audit history

        return callingUser.memberOfCNs.any { viewAuditAdminGroupCNs.contains(it) }
    }

    open class AccessDeniedError(description: String) :
        ApiError(HttpStatusCode.Forbidden, "forbidden", description, description)
}
