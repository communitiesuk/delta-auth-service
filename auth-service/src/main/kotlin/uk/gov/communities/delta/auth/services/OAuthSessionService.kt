package uk.gov.communities.delta.auth.services

import io.ktor.server.auth.*
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.jetbrains.annotations.Blocking
import org.slf4j.LoggerFactory
import org.slf4j.spi.LoggingEventBuilder
import uk.gov.communities.delta.auth.config.DeltaLoginEnabledClient
import uk.gov.communities.delta.auth.repositories.DbPool
import uk.gov.communities.delta.auth.utils.TimeSource
import uk.gov.communities.delta.auth.utils.hashBase64String
import uk.gov.communities.delta.auth.utils.randomBase64
import java.sql.Timestamp
import java.time.Instant
import java.util.*
import kotlin.time.Duration.Companion.hours

data class OAuthSession(
    val id: Int, // Our internal database id, no relation to the value of the SESSIONID cookie in Delta, or sessionId from Delta's logs
    val userCn: String,
    val userGUID: UUID?, // TODO DT-976-2 - make this not nullable
    val client: DeltaLoginEnabledClient,
    val authToken: String,
    val createdAt: Instant,
    val traceId: String,
    val isSso: Boolean,
    val impersonatedUserCn: String? = null,
    val impersonatedUserGUID: UUID?,
) : Principal {
    fun expired(timeSource: TimeSource) =
        createdAt.plusSeconds(OAuthSessionService.TOKEN_VALID_DURATION_SECONDS) < timeSource.now()

    suspend fun getUserGUID(userLookupService: UserLookupService): UUID {
        return this.userGUID ?: userLookupService.lookupUserByCn(this.userCn).getUUID() // TODO DT-976-2 - no longer needed
    }
}

interface IOAuthSessionService {
    suspend fun create(authCode: AuthCode, client: DeltaLoginEnabledClient): OAuthSession
    suspend fun retrieveFomAuthToken(authToken: String, client: DeltaLoginEnabledClient): OAuthSession?
}

class OAuthSessionService(private val dbPool: DbPool, private val timeSource: TimeSource) : IOAuthSessionService {
    private val logger = LoggerFactory.getLogger(javaClass)

    companion object {
        val TOKEN_VALID_DURATION_SECONDS = 12.hours.inWholeSeconds
        const val TOKEN_LENGTH_BYTES = 24
    }

    override suspend fun create(authCode: AuthCode, client: DeltaLoginEnabledClient): OAuthSession {
        val token = randomBase64(TOKEN_LENGTH_BYTES)
        val now = timeSource.now()
        val deltaSession = withContext(Dispatchers.IO) { insert(authCode, client, token, now) }

        logger.atInfo().withSession(deltaSession).log("Generated session at {}", now)
        return deltaSession
    }


    override suspend fun retrieveFomAuthToken(authToken: String, client: DeltaLoginEnabledClient): OAuthSession? {
        val session = withContext(Dispatchers.IO) { select(authToken, client) } ?: return null
        if (session.expired(timeSource)) {
            logger.atInfo().withSession(session).log("Session expired. Crated at {}", session.createdAt)
            return null
        }
        logger.atDebug().withSession(session).log("Retrieved session from auth token")
        return session
    }

    @Blocking
    private fun insert(authCode: AuthCode, client: DeltaLoginEnabledClient, token: String, now: Instant): OAuthSession {
        return dbPool.useConnectionBlocking("Insert delta_session") {
            val stmt = it.prepareStatement(
                "INSERT INTO delta_session (username, client_id, auth_token_hash, created_at, trace_id, is_sso, user_guid) " +
                    "VALUES (?, ?, ?, ?, ?, ?, ?) RETURNING id"
            )
            stmt.setString(1, authCode.userCn)
            stmt.setString(2, client.clientId)
            stmt.setBytes(3, hashBase64String(token))
            stmt.setTimestamp(4, Timestamp.from(now))
            stmt.setString(5, authCode.traceId)
            stmt.setBoolean(6, authCode.isSso)
            stmt.setObject(7, authCode.userGUID)
            val result = stmt.executeQuery()
            if (!result.next()) throw Exception("Expected one result")
            val id = result.getInt(1)
            it.commit()
            OAuthSession(
                id = id,
                userCn = authCode.userCn,
                userGUID = authCode.userGUID,
                client = client,
                authToken = token,
                createdAt = now,
                traceId = authCode.traceId,
                isSso = authCode.isSso,
                impersonatedUserCn = null,
                impersonatedUserGUID = null,
            )
        }
    }

    @Blocking
    fun updateWithImpersonatedCn(sessionId: Int, impersonatedUserCn: String, impersonatedUserGUID: UUID?) {
        dbPool.useConnectionBlocking("impersonate_user") {
            val stmt = it.prepareStatement("UPDATE delta_session SET impersonated_user_cn = ?, impersonated_user_guid = ? WHERE id = ?")
            stmt.setString(1, impersonatedUserCn)
            stmt.setObject(2, impersonatedUserGUID)
            stmt.setInt(3, sessionId)
            val result = stmt.executeUpdate()
            if (result != 1) throw Exception("Expected to change only 1 row but was $result")
            it.commit()
        }
    }

    @Blocking
    private fun select(authToken: String, client: DeltaLoginEnabledClient): OAuthSession? {
        return dbPool.useConnectionBlocking("Read delta_session") {
            val stmt =
                it.prepareStatement(
                    "SELECT id, username, client_id, created_at, trace_id, is_sso, impersonated_user_cn, user_guid, impersonated_user_guid " +
                            "FROM delta_session WHERE auth_token_hash = ? AND client_id = ?"
                )
            stmt.setBytes(1, hashBase64String(authToken))
            stmt.setString(2, client.clientId)
            val result = stmt.executeQuery()
            if (!result.next()) {
                logger.debug("No session found for auth token '{}' and client '{}'", authToken, client.clientId)
                null
            } else {

                OAuthSession(
                    id = result.getInt("id"),
                    userCn = result.getString("username"),
                    userGUID = result.getObject("user_guid", UUID::class.java),
                    client = client,
                    authToken = authToken,
                    createdAt = result.getTimestamp("created_at").toInstant(),
                    traceId = result.getString("trace_id"),
                    isSso = result.getBoolean("is_sso"),
                    impersonatedUserCn = result.getString("impersonated_user_cn"),
                    impersonatedUserGUID = result.getObject("impersonated_user_guid", UUID::class.java),
                )
            }
        }
    }
}

fun LoggingEventBuilder.withSession(session: OAuthSession): LoggingEventBuilder =
    addKeyValue("username", session.userCn)
        .addKeyValue("oauthSession", session.id)
        .addKeyValue("trace", session.traceId)
