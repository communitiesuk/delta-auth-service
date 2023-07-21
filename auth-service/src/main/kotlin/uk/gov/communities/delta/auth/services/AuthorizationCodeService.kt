package uk.gov.communities.delta.auth.services

import net.logstash.logback.argument.StructuredArguments
import org.slf4j.LoggerFactory
import java.sql.Timestamp
import java.time.Instant

interface IAuthorizationCodeService {
    fun generateAndStore(userCn: String, traceId: String): String
    fun lookupAndInvalidate(code: String): AuthCode?
}

// The authorization code is the base64 value we include in the URL when we redirect back to the Delta website
// It's a short-lived code that can be exchanged using the token endpoint for user details and a longer lived access token
// https://datatracker.ietf.org/doc/html/rfc6749#section-4.1
// We didn't strictly need to use OAuth since we implement back-channel communication with Delta easily,
// but it's well understood and means we can use standard libraries on the Delta side
// Assume we only have one client (delta-website) so we don't store it
data class AuthCode(val code: String, val userCn: String, val createdAt: Instant, val traceId: String) {
    fun expired() = createdAt.plusSeconds(AuthorizationCodeService.AUTH_CODE_VALID_DURATION_SECONDS) < Instant.now()
}

class AuthorizationCodeService(private val dbPool: DbPool) : IAuthorizationCodeService {
    private val logger = LoggerFactory.getLogger(javaClass)

    companion object {
        const val AUTH_CODE_VALID_DURATION_SECONDS = 30L
        const val AUTH_CODE_LENGTH_BYTES = 24
    }

    override fun generateAndStore(userCn: String, traceId: String): String {
        val code = randomBase64(AUTH_CODE_LENGTH_BYTES)
        val now = Instant.now()
        val authCode = AuthCode(code, userCn, now, traceId)
        insert(authCode)

        logger.info("Generated auth code for user {} at {}", StructuredArguments.keyValue("username", userCn), now)
        return code
    }

    override fun lookupAndInvalidate(code: String): AuthCode? {
        val entry = deleteReturning(code) ?: return null
        if (entry.expired()) {
            logger.warn("Expired auth code {} for user {}", code, entry.userCn)
            return null
        }
        return entry
    }

    private fun insert(authCode: AuthCode) {
        dbPool.connection().use {
            val stmt = it.prepareStatement(
                "INSERT INTO authorization_code (username, code_hash, created_at, trace_id) " +
                        "VALUES (?, ?, ?, ?)"
            )
            stmt.setString(1, authCode.userCn)
            stmt.setBytes(2, hashBase64String(authCode.code))
            stmt.setTimestamp(3, Timestamp.from(authCode.createdAt))
            stmt.setString(4, authCode.traceId)
            stmt.executeUpdate()
            it.commit()
        }
    }

    private fun deleteReturning(code: String): AuthCode? {
        val codeHash = try {
            hashBase64String(code)
        } catch (e: IllegalArgumentException) {
            logger.error("Auth code '{}' is not a valid base64 string", code, e)
            return null
        }
        return dbPool.useConnection {
            val stmt = it.prepareStatement(
                "DELETE FROM authorization_code " +
                        "WHERE code_hash = ? RETURNING username, created_at, trace_id"
            )
            stmt.setBytes(1, codeHash)
            val resultSet = stmt.executeQuery()
            if (!resultSet.next()) {
                logger.debug("Code not found {}", code)
                return@useConnection null
            }
            val authCode = AuthCode(
                code = code,
                userCn = resultSet.getString("username"),
                createdAt = resultSet.getTimestamp("created_at").toInstant(),
                traceId = resultSet.getString("trace_id")
            )
            it.commit()
            return@useConnection authCode
        }
    }
}
