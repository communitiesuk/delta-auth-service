package uk.gov.communities.delta.auth.repositories

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonObject
import org.jetbrains.annotations.Blocking
import java.sql.Connection
import java.sql.ResultSet
import java.sql.Timestamp
import java.util.*
import java.time.Instant

class UserAuditTrailRepo {
    enum class AuditAction(val action: String) {
        // Modifying or removing an existing action requires a database migration to update old records
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

        return stmt.executeQuery().map(::mapUserAuditRow)
    }

    @Blocking
    fun getAuditForAllUsers(conn: Connection, from: Instant, to: Instant): List<UserAuditRow> {
        val stmt = conn.prepareStatement(
            "SELECT action, timestamp, user_cn, editing_user_cn, request_id, action_data " +
                "FROM user_audit " +
                "WHERE timestamp >= ? " +
                "AND timestamp < ? " +
                "ORDER BY timestamp DESC "
        )
        stmt.setTimestamp(1, Timestamp.from(from))
        stmt.setTimestamp(2, Timestamp.from(to))

        return stmt.executeQuery().map(::mapUserAuditRow)
    }

    private fun mapUserAuditRow(row: ResultSet) = UserAuditRow(
        AuditAction.fromActionString(row.getString("action")),
        row.getTimestamp("timestamp"),
        row.getString("user_cn"),
        row.getString("editing_user_cn"),
        row.getString("request_id"),
        Json.parseToJsonElement(row.getString("action_data")).jsonObject,
    )

    @Blocking
    fun getAuditItemCount(conn: Connection, userCn: String): Int {
        val stmt = conn.prepareStatement(
            "SELECT COUNT(*) " +
                "FROM user_audit " +
                "WHERE user_cn = ?"
        )
        stmt.setString(1, userCn)
        val resultSet = stmt.executeQuery()
        resultSet.next()
        return resultSet.getInt(1)
    }

    @Blocking
    fun insertAuditRow(
        conn: Connection,
        action: AuditAction,
        userCn: String,
        userGUID: UUID?,
        editingUserCn: String?,
        editingUserGUID: UUID?,
        requestId: String,
        encodedActionData: String,
    ) {
        val stmt = conn.prepareStatement(
            "INSERT INTO user_audit (action, timestamp, user_cn, editing_user_cn, request_id, action_data, user_guid, editing_user_guid) VALUES " +
                "(?, now(), ?, ?, ?, ? ::jsonb, ?, ?)"
        )
        stmt.setString(1, action.action)
        stmt.setString(2, userCn)
        stmt.setString(3, editingUserCn)
        stmt.setString(4, requestId)
        stmt.setString(5, encodedActionData)
        stmt.setObject(6, userGUID)
        stmt.setObject(7, editingUserGUID)
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
