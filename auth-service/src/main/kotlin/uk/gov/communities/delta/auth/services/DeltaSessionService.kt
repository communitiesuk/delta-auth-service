package uk.gov.communities.delta.auth.services

import net.logstash.logback.argument.StructuredArguments.keyValue
import org.slf4j.LoggerFactory
import java.sql.Timestamp
import java.time.Instant
import kotlin.time.Duration.Companion.hours

data class DeltaSession(
    val id: Int, // Our internal database id, no relation to the value of the SESSIONID cookie in Delta, or sessionId from Delta's logs
    val userCn: String,
    val authToken: String,
    val createdAt: Instant,
) {
    fun expired() = createdAt.plusSeconds(DeltaSessionService.TOKEN_VALID_DURATION_SECONDS) < Instant.now()
}

interface IDeltaSessionService {
    fun create(authCode: AuthCode): DeltaSession
    fun retrieveFomAuthToken(authToken: String): DeltaSession?
}

class DeltaSessionService(private val dbPool: DbPool) : IDeltaSessionService {
    private val logger = LoggerFactory.getLogger(javaClass)

    companion object {
        val TOKEN_VALID_DURATION_SECONDS = 12.hours.inWholeSeconds
        const val TOKEN_LENGTH_BYTES = 24
    }

    override fun create(authCode: AuthCode): DeltaSession {
        val token = randomBase64(TOKEN_LENGTH_BYTES)
        val now = Instant.now()
        val deltaSession = insert(authCode.userCn, token, now)

        logger.info(
            "Generated auth code for user {} with id {} at {}",
            keyValue("username", authCode.userCn),
            keyValue("deltaSessionId", deltaSession.id),
            now
        )
        return deltaSession
    }

    override fun retrieveFomAuthToken(authToken: String): DeltaSession? {
        val session = select(authToken) ?: return null
        if (session.expired()) {
            logger.info(
                "Session with id {} for user {} is expired. Crated at {}",
                keyValue("deltaSessionId", session.id),
                keyValue("username", session.userCn),
                session.createdAt
            )
            return null
        }
        return session
    }

    private fun insert(username: String, token: String, now: Instant): DeltaSession {
        return dbPool.useConnection {
            val stmt = it.prepareStatement(
                "INSERT INTO delta_session (username, auth_token_hash, created_at) " +
                        "VALUES (?, ?, ?) RETURNING id"
            )
            stmt.setString(1, username)
            stmt.setBytes(2, hashBase64String(token))
            stmt.setTimestamp(3, Timestamp.from(now))
            val result = stmt.executeQuery()
            if (!result.next()) throw Exception("Expected one result")
            val id = result.getInt(1)
            it.commit()
            DeltaSession(id = id, userCn = username, authToken = token, createdAt = now)
        }
    }

    private fun select(authToken: String): DeltaSession? {
        return dbPool.useConnection {
            val stmt =
                it.prepareStatement("SELECT id, username, created_at FROM delta_session WHERE auth_token_hash = ?")
            stmt.setBytes(1, hashBase64String(authToken))
            val result = stmt.executeQuery()
            if (!result.next()) {
                logger.debug("No session found for auth token '{}'", authToken)
                null
            } else {
                DeltaSession(
                    id = result.getInt("id"),
                    userCn = result.getString("username"),
                    authToken = authToken,
                    createdAt = result.getTimestamp("created_at").toInstant(),
                )
            }
        }
    }
}
