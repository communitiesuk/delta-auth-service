package uk.gov.communities.delta.auth.repositories

import org.jetbrains.annotations.Blocking
import uk.gov.communities.delta.auth.plugins.NoUserException
import java.sql.Connection
import java.util.*

class UserGUIDMapRepo {

    @Blocking
    fun getCNForUser(conn: Connection, userGUID: UUID): String {
        val stmt = conn.prepareStatement("SELECT user_cn FROM user_guid_map WHERE user_guid = ?")
        stmt.setObject(1, userGUID)
        val result = stmt.executeQuery()
        if (!result.next()) throw NoUserException("No user found with GUID $userGUID")
        else return result.getString("user_cn")
    }

    @Blocking
    fun getGUIDForUser(conn: Connection, userCN: String): UUID {
        val stmt = conn.prepareStatement("SELECT user_guid FROM user_guid_map WHERE user_cn = ?")
        stmt.setObject(1, userCN)
        val result = stmt.executeQuery()
        if (!result.next()) throw NoUserException("No user found with userCN $userCN")
        else return result.getObject("user_guid", UUID::class.java)
    }

    @Blocking
    fun updateUser(conn: Connection, user: LdapUser, newUserCN: String) {
        val stmt = conn.prepareStatement("UPDATE user_guid_map SET user_cn = ? WHERE user_guid = ?")
        stmt.setString(1, newUserCN)
        stmt.setObject(2, user.getGUID())
        val result = stmt.executeUpdate()
        if (result == 0)
        // NB: this should not be seen in production or staging but may occur on test or dev due to shared AD
            addMissingUser(conn, user, newUserCN)
        else if (result != 1) throw Exception("Expected to change only 1 row but was $result")
    }

    @Blocking
    fun addMissingUser(conn: Connection, user: LdapUser, newUserCN: String? = null) {
        // NB: this should not need to be used in production or staging but may occur on test or dev due to shared AD
        addRow(conn, newUserCN ?: user.cn, user.getGUID())
    }

    @Blocking
    fun newUser(conn: Connection, user: LdapUser) {
        addRow(conn, user.cn, user.getGUID())
    }

    @Blocking
    private fun addRow(conn: Connection, userCN: String, userGUID: UUID) {
        val stmt = conn.prepareStatement(
            "INSERT INTO user_guid_map (user_guid, user_cn) VALUES (?, ?) " +
                "ON CONFLICT (user_guid) DO UPDATE SET user_cn = ?"
        )
        stmt.setObject(1, userGUID)
        stmt.setString(2, userCN)
        stmt.setString(3, userCN)
        stmt.executeUpdate()
    }
}
