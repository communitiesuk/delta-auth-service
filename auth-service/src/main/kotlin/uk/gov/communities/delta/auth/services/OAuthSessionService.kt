package uk.gov.communities.delta.auth.services

import org.slf4j.LoggerFactory
import org.slf4j.spi.LoggingEventBuilder
import java.sql.Timestamp
import java.time.Instant
import kotlin.time.Duration.Companion.hours

data class OAuthSession(
    val id: Int, // Our internal database id, no relation to the value of the SESSIONID cookie in Delta, or sessionId from Delta's logs
    val userCn: String,
    val authToken: String,
    val createdAt: Instant,
    val traceId: String,
) {
    fun expired() = createdAt.plusSeconds(OAuthSessionService.TOKEN_VALID_DURATION_SECONDS) < Instant.now()
}

interface IOAuthSessionService {
    fun create(authCode: AuthCode): OAuthSession
    fun retrieveFomAuthToken(authToken: String): OAuthSession?
}

class OAuthSessionService(private val dbPool: DbPool) : IOAuthSessionService {
    private val logger = LoggerFactory.getLogger(javaClass)

    companion object {
        val TOKEN_VALID_DURATION_SECONDS = 12.hours.inWholeSeconds
        const val TOKEN_LENGTH_BYTES = 24
    }

    override fun create(authCode: AuthCode): OAuthSession {
        val token = randomBase64(TOKEN_LENGTH_BYTES)
        val now = Instant.now()
        val deltaSession = insert(authCode, token, now)

        logger.atInfo().withSession(deltaSession).log("Generated session at {}", now)
        return deltaSession
    }

    override fun retrieveFomAuthToken(authToken: String): OAuthSession? {
        val session = select(authToken) ?: return null
        if (session.expired()) {
            logger.atInfo().withSession(session).log("Session expired. Crated at {}", session.createdAt)
            return null
        }
        return session
    }

    private fun insert(authCode: AuthCode, token: String, now: Instant): OAuthSession {
        return dbPool.useConnection {
            val stmt = it.prepareStatement(
                "INSERT INTO delta_session (username, auth_token_hash, created_at, trace_id) " +
                        "VALUES (?, ?, ?, ?) RETURNING id"
            )
            stmt.setString(1, authCode.userCn)
            stmt.setBytes(2, hashBase64String(token))
            stmt.setTimestamp(3, Timestamp.from(now))
            stmt.setString(4, authCode.traceId)
            val result = stmt.executeQuery()
            if (!result.next()) throw Exception("Expected one result")
            val id = result.getInt(1)
            it.commit()
            OAuthSession(
                id = id,
                userCn = authCode.userCn,
                authToken = token,
                createdAt = now,
                traceId = authCode.traceId
            )
        }
    }

    private fun select(authToken: String): OAuthSession? {
        return dbPool.useConnection {
            val stmt =
                it.prepareStatement("SELECT id, username, created_at, trace_id FROM delta_session WHERE auth_token_hash = ?")
            stmt.setBytes(1, hashBase64String(authToken))
            val result = stmt.executeQuery()
            if (!result.next()) {
                logger.debug("No session found for auth token '{}'", authToken)
                null
            } else {
                OAuthSession(
                    id = result.getInt("id"),
                    userCn = result.getString("username"),
                    authToken = authToken,
                    createdAt = result.getTimestamp("created_at").toInstant(),
                    traceId = result.getString("trace_id"),
                )
            }
        }
    }
}

fun LoggingEventBuilder.withSession(session: OAuthSession): LoggingEventBuilder =
    addKeyValue("username", session.userCn)
        .addKeyValue("oauthSession", session.id)
        .addKeyValue("trace", session.traceId)
