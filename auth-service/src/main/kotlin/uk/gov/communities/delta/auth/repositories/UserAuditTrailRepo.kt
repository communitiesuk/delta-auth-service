package uk.gov.communities.delta.auth.repositories

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonObject
import org.jetbrains.annotations.Blocking
import java.sql.Connection
import java.sql.ResultSet
import java.sql.Timestamp

class UserAuditTrailRepo {
    enum class AuditAction(val action: String) {
        FORM_LOGIN("form_login"),
        SSO_LOGIN("sso_login"),
        RESET_PASSWORD_EMAIL("reset_password_email"),
        SET_PASSWORD_EMAIL("set_password_email"),
        RESET_PASSWORD("reset_password"),
        SET_PASSWORD("set_password"),
        USER_CREATED_BY_SELF_REGISTER("user_created_by_self_register"),
        USER_CREATED_BY_SSO("user_created_by_sso"),
        USER_CREATED_BY_ADMIN("user_created_by_admin"),
        SSO_USER_CREATED_BY_ADMIN("sso_user_created_by_admin"),
        USER_UPDATE("user_update"),
        USER_ENABLE_BY_ADMIN("user_enable_by_admin"),
        USER_DISABLE_BY_ADMIN("user_disable_by_admin"),
        IMPERSONATE_USER("impersonate_user"),
        ;

        companion object {
            fun fromActionString(s: String) = entries.first { it.action == s }
        }
    }

    @Blocking
    fun getAuditForUser(conn: Connection, userCn: String, limitOffset: Pair<Int, Int>? = null): List<UserAuditRow> {
        val stmt = conn.prepareStatement(
            "SELECT action, timestamp, user_cn, editing_user_cn, request_id, action_data " +
                    "FROM user_audit WHERE user_cn = ? " +
                    "ORDER BY timestamp DESC " +
                    if (limitOffset != null) "LIMIT ? OFFSET ?" else ""
        )
        stmt.setString(1, userCn)
        if (limitOffset != null) {
            stmt.setInt(2, limitOffset.first)
            stmt.setInt(3, limitOffset.second)
        }

        return stmt.executeQuery().map {
            UserAuditRow(
                AuditAction.fromActionString(it.getString("action")),
                it.getTimestamp("timestamp"),
                it.getString("user_cn"),
                it.getString("editing_user_cn"),
                it.getString("request_id"),
                Json.parseToJsonElement(it.getString("action_data")).jsonObject,
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
        val actionData: JsonObject,
    )
}

fun <T> ResultSet.map(m: (ResultSet) -> T): List<T> {
    val result = mutableListOf<T>()
    while (this.next()) {
        result.add(m(this))
    }
    return result
}
