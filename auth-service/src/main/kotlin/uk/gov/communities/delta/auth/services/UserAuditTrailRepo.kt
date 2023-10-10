package uk.gov.communities.delta.auth.services

import io.ktor.server.application.*
import io.ktor.server.plugins.callid.*
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement
import org.jetbrains.annotations.Blocking
import uk.gov.communities.delta.auth.config.AzureADSSOClient
import java.sql.Connection
import java.sql.ResultSet
import java.sql.Timestamp

class UserAuditTrailRepo {
    enum class AuditAction(val action: String) {
        FORM_LOGIN("form_login"),
        SSO_LOGIN("sso_login");

        companion object {
            fun fromActionString(s: String) = entries.first { it.action == s }
        }
    }

    @Blocking
    fun userFormLoginAudit(conn: Connection, userCn: String, call: ApplicationCall) {
        insertAuditRow<Unit>(conn, AuditAction.FORM_LOGIN, userCn, null, call.callId!!, null)
    }

    @Blocking
    fun userSSOLoginAudit(
        conn: Connection,
        userCn: String,
        ssoClient: AzureADSSOClient,
        azureUserObjectId: String,
        call: ApplicationCall,
    ) {
        insertAuditRow(
            conn, AuditAction.SSO_LOGIN, userCn, null, call.callId!!, SSOLoginAuditData(
                ssoClient.internalId, azureUserObjectId
            )
        )
    }

    @Blocking
    fun getAuditForUser(conn: Connection, userCn: String): List<UserAuditRow> {
        val stmt = conn.prepareStatement(
            "SELECT action, timestamp, user_cn, editing_user_cn, request_id, action_data " +
                    "FROM user_audit WHERE user_cn = ?"
        )
        stmt.setString(1, userCn)

        return stmt.executeQuery().map {
            UserAuditRow(
                AuditAction.fromActionString(it.getString("action")),
                it.getTimestamp("timestamp"),
                it.getString("user_cn"),
                it.getString("editing_user_cn"),
                it.getString("request_id"),
                Json.parseToJsonElement(it.getString("action_data")),
            )
        }
    }

    @Blocking
    private inline fun <reified T>insertAuditRow(
        conn: Connection,
        action: AuditAction,
        userCn: String,
        editingUserCn: String?,
        requestId: String,
        actionData: T?,
    ) {
        val stmt = conn.prepareStatement(
            "INSERT INTO user_audit (action, timestamp, user_cn, editing_user_cn, request_id, action_data) VALUES " +
                    "(?, now(), ?, ?, ?, ? ::jsonb)"
        )
        stmt.setString(1, action.action)
        stmt.setString(2, userCn)
        stmt.setString(3, editingUserCn)
        stmt.setString(4, requestId)
        stmt.setString(5, if (actionData == null) "{}" else Json.encodeToString<T>(actionData))
        stmt.executeUpdate()
    }

    data class UserAuditRow(
        val action: AuditAction,
        val timestamp: Timestamp,
        val userCn: String,
        val editingUserCn: String?,
        val requestId: String,
        val actionData: JsonElement,
    )

    @Serializable
    private data class SSOLoginAuditData(val ssoClientId: String, val azureUserObjectId: String)
}

fun <T> ResultSet.map(m: (ResultSet) -> T): List<T> {
    val result = mutableListOf<T>()
    while (this.next()) {
        result.add(m(this))
    }
    return result
}
