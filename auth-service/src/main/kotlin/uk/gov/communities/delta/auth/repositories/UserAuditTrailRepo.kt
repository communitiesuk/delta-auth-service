package uk.gov.communities.delta.auth.repositories

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement
import org.jetbrains.annotations.Blocking
import java.sql.Connection
import java.sql.ResultSet
import java.sql.Timestamp

class UserAuditTrailRepo {
    enum class AuditAction(val action: String) {
        FORM_LOGIN("form_login"),
        SSO_LOGIN("sso_login"),
        FORGOT_PASSWORD_EMAIL("forgot_password_email"),
        SET_PASSWORD_EMAIL("set_password_email"),
        RESET_PASSWORD("reset_password"),
        SET_PASSWORD("set_password"),
        SELF_REGISTER("self_register"),
        SSO_USER_CREATED("sso_user_created"),
        ;

        companion object {
            fun fromActionString(s: String) = entries.first { it.action == s }
        }
    }

    @Blocking
    fun getAuditForUser(conn: Connection, userCn: String): List<UserAuditRow> {
        val stmt = conn.prepareStatement(
            "SELECT action, timestamp, user_cn, editing_user_cn, request_id, action_data " +
                    "FROM user_audit WHERE user_cn = ? " +
                    "ORDER BY timestamp"
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
    fun insertAuditRow(
        conn: Connection,
        action: AuditAction,
        userCn: String,
        editingUserCn: String?,
        requestId: String,
        encodedActionData: String,
    ) {
        val stmt = conn.prepareStatement(
            "INSERT INTO user_audit (action, timestamp, user_cn, editing_user_cn, request_id, action_data) VALUES " +
                    "(?, now(), ?, ?, ?, ? ::jsonb)"
        )
        stmt.setString(1, action.action)
        stmt.setString(2, userCn)
        stmt.setString(3, editingUserCn)
        stmt.setString(4, requestId)
        stmt.setString(5, encodedActionData)
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
}

fun <T> ResultSet.map(m: (ResultSet) -> T): List<T> {
    val result = mutableListOf<T>()
    while (this.next()) {
        result.add(m(this))
    }
    return result
}
