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
    fun getAuditForUser(conn: Connection, userGUID: UUID, limitOffset: Pair<Int, Int>? = null): List<UserAuditRow> {
        val stmt = conn.prepareStatement(
            "SELECT action, timestamp, ugm_user.user_cn AS user_cn, user_audit.user_guid, " +
                "ugm_editing_user.user_cn AS editing_user_cn, editing_user_guid, request_id, action_data " +
                "FROM user_audit " +
                "LEFT JOIN user_guid_map ugm_user ON user_audit.user_guid = ugm_user.user_guid " +
                "LEFT JOIN user_guid_map ugm_editing_user ON user_audit.editing_user_guid = ugm_editing_user.user_guid " +
                "WHERE user_audit.user_guid = ? " +
                "ORDER BY timestamp DESC " +
                    if (limitOffset != null) "LIMIT ? OFFSET ?" else ""
        )
        stmt.setObject(1, userGUID)
        if (limitOffset != null) {
            stmt.setInt(2, limitOffset.first)
            stmt.setInt(3, limitOffset.second)
        }

        return stmt.executeQuery().map(::mapUserAuditRow)
    }

    @Blocking
    fun getAuditForAllUsers(conn: Connection, from: Instant, to: Instant): List<UserAuditRow> {
        val stmt = conn.prepareStatement(
            "SELECT action, timestamp, ugm_user.user_cn AS user_cn, user_audit.user_guid, " +
                "ugm_editing_user.user_cn AS editing_user_cn, editing_user_guid, request_id, action_data " +
                "FROM user_audit " +
                "LEFT JOIN user_guid_map ugm_user ON user_audit.user_guid = ugm_user.user_guid " +
                "LEFT JOIN user_guid_map ugm_editing_user ON user_audit.editing_user_guid = ugm_editing_user.user_guid " +
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
        row.getString("user_cn")?:"",
        row.getObject("user_guid", UUID::class.java),
        row.getString("editing_user_cn"),
        row.getObject("editing_user_guid", UUID::class.java),
        row.getString("request_id"),
        Json.parseToJsonElement(row.getString("action_data")).jsonObject,
    )

    @Blocking
    fun getAuditItemCount(conn: Connection, userGUID: UUID): Int {
        val stmt = conn.prepareStatement(
            "SELECT COUNT(*) " +
                "FROM user_audit " +
                "WHERE user_guid = ?"
        )
        stmt.setObject(1, userGUID)
        val resultSet = stmt.executeQuery()
        resultSet.next()
        return resultSet.getInt(1)
    }

    @Blocking
    fun insertAuditRow(
        conn: Connection,
        action: AuditAction,
        userGUID: UUID,
        editingUserGUID: UUID?,
        requestId: String,
        encodedActionData: String,
    ) {
        val stmt = conn.prepareStatement(
            "INSERT INTO user_audit (action, timestamp, request_id, action_data, user_guid, editing_user_guid) " +
                "VALUES (?, now(), ?, ? ::jsonb, ?, ?)"
        )
        stmt.setString(1, action.action)
        stmt.setString(2, requestId)
        stmt.setString(3, encodedActionData)
        stmt.setObject(4, userGUID)
        stmt.setObject(5, editingUserGUID)
        stmt.executeUpdate()
    }

    data class UserAuditRow(
        val action: AuditAction,
        val timestamp: Timestamp,
        val userCN: String,
        val userGUID: UUID,
        val editingUserCN: String?,
        val editingUserGUID: UUID?,
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
