package uk.gov.communities.delta.auth.services

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.jetbrains.annotations.Blocking
import org.slf4j.LoggerFactory
import org.slf4j.spi.LoggingEventBuilder
import uk.gov.communities.delta.auth.config.Client
import uk.gov.communities.delta.auth.utils.TimeSource
import java.sql.Timestamp
import java.time.Instant

// The authorization code is the value we include in the URL when we redirect back to the Delta website
// It's a short-lived code that can be exchanged using the token endpoint for user details and a longer lived access token
data class AuthCode(
    val code: String,
    val userCn: String,
    val client: Client,
    val createdAt: Instant,
    val traceId: String,
) {
    fun expired(timeSource: TimeSource) =
        createdAt.plusSeconds(AuthorizationCodeService.AUTH_CODE_VALID_DURATION_SECONDS) < timeSource.now()
}

class AuthorizationCodeService(private val dbPool: DbPool, private val timeSource: TimeSource) {
    private val logger = LoggerFactory.getLogger(javaClass)

    companion object {
        const val AUTH_CODE_VALID_DURATION_SECONDS = 30L
        const val AUTH_CODE_LENGTH_BYTES = 24
    }

    suspend fun generateAndStore(userCn: String, client: Client, traceId: String): AuthCode {
        val code = randomBase64(AUTH_CODE_LENGTH_BYTES)
        val now = timeSource.now()
        val authCode = AuthCode(code, userCn, client, now, traceId)
        withContext(Dispatchers.IO) { insert(authCode) }

        logger.atInfo().withAuthCode(authCode).log("Generated auth code at {}", now)
        return authCode
    }

    suspend fun lookupAndInvalidate(code: String, client: Client): AuthCode? {
        val entry = withContext(Dispatchers.IO) { deleteReturning(code, client) } ?: return null
        if (entry.expired(timeSource)) {
            logger.atWarn().withAuthCode(entry).log("Expired auth code '{}'", code)
            return null
        }
        return entry
    }

    @Blocking
    private fun insert(authCode: AuthCode) {
        dbPool.useConnection {
            val stmt = it.prepareStatement(
                "INSERT INTO authorization_code (username, client_id, code_hash, created_at, trace_id) " +
                        "VALUES (?, ?, ?, ?, ?)"
            )
            stmt.setString(1, authCode.userCn)
            stmt.setString(2, authCode.client.clientId)
            stmt.setBytes(3, hashBase64String(authCode.code))
            stmt.setTimestamp(4, Timestamp.from(authCode.createdAt))
            stmt.setString(5, authCode.traceId)
            stmt.executeUpdate()
            it.commit()
        }
    }

    @Blocking
    private fun deleteReturning(code: String, client: Client): AuthCode? {
        val codeHash = try {
            hashBase64String(code)
        } catch (e: IllegalArgumentException) {
            logger.error("Auth code '{}' is not a valid base64 string", code, e)
            return null
        }
        return dbPool.useConnection {
            val stmt = it.prepareStatement(
                "DELETE FROM authorization_code " +
                        "WHERE code_hash = ? AND client_id = ? RETURNING username, created_at, trace_id"
            )
            stmt.setBytes(1, codeHash)
            stmt.setString(2, client.clientId)
            val resultSet = stmt.executeQuery()
            if (!resultSet.next()) {
                logger.debug("Code not found '{}' for client '{}'", code, client.clientId)
                return@useConnection null
            }
            val authCode = AuthCode(
                code = code,
                userCn = resultSet.getString("username"),
                client = client,
                createdAt = resultSet.getTimestamp("created_at").toInstant(),
                traceId = resultSet.getString("trace_id")
            )
            it.commit()
            return@useConnection authCode
        }
    }
}

fun LoggingEventBuilder.withAuthCode(authCode: AuthCode): LoggingEventBuilder =
    addKeyValue("username", authCode.code).addKeyValue("trace", authCode.traceId)
