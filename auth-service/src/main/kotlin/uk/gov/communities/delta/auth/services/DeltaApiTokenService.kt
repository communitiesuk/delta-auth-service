package uk.gov.communities.delta.auth.services

import io.ktor.server.application.*
import org.jetbrains.annotations.Blocking
import org.slf4j.LoggerFactory
import uk.gov.communities.delta.auth.repositories.DbPool
import uk.gov.communities.delta.auth.utils.TimeSource
import uk.gov.communities.delta.auth.utils.hashBase64String
import uk.gov.communities.delta.auth.utils.randomBase64
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.sql.Timestamp
import java.time.Instant
import java.time.temporal.ChronoUnit
import java.util.*

class DeltaApiTokenService(
    private val dbPool: DbPool,
    private val timeSource: TimeSource,
    private val userAuditService: UserAuditService,
) {
    private val logger = LoggerFactory.getLogger(javaClass)

    suspend fun validateApiClientIdAndSecret(id: String, secret: String): Boolean {
        return dbPool.useConnectionNonBlocking("Validate client id and secret") {
            val stmt = it.prepareStatement(
                "SELECT client_secret FROM api_clients " +
                    "WHERE client_id = ?"
            )
            stmt.setString(1, id)
            val result = stmt.executeQuery()
            if (!result.next()) {
                false
            } else {
                val secretBytes = secret.toByteArray(StandardCharsets.UTF_8)
                val referenceBytes = result.getString("client_secret").toByteArray(StandardCharsets.UTF_8)
                MessageDigest.isEqual(secretBytes, referenceBytes)
            }
        }
    }

    suspend fun createAndStoreApiToken(username: String, clientId: String, userGuid: UUID, call: ApplicationCall): String {
        logger.atInfo().addKeyValue("clientId", clientId).log("Creating new API token for client")
        val apiToken = randomBase64(32)

        insertApiToken(apiToken, timeSource.now(), username, userGuid, clientId, call)
        return apiToken
    }

    suspend fun validateApiToken(apiToken: String): Triple<String, String, UUID>? {
        return dbPool.useConnectionNonBlocking("Validate client id and secret") {
            val stmt = it.prepareStatement(
                "SELECT created_at, created_by_user_cn, created_by_client_id, created_by_user_guid FROM api_tokens " +
                    "WHERE token_hash = ? AND created_at > ?"
            )
            stmt.setBytes(1, hashBase64String(apiToken))
            val earliestValidCreationTime = timeSource.now().plus(-API_TOKEN_EXPIRY_HOURS, ChronoUnit.HOURS)
            stmt.setTimestamp(2, Timestamp.from(earliestValidCreationTime))
            val result = stmt.executeQuery()
            if (!result.next()) {
                null
            } else {
                Triple(
                    result.getString("created_by_user_cn"),
                    result.getString("created_by_client_id"),
                    UUID.fromString(result.getString("created_by_user_guid"))
                )
            }
        }
    }

    @Blocking
    private suspend fun insertApiToken(token: String, now: Instant, username: String, userGuid: UUID, clientId: String, call: ApplicationCall) {
        userAuditService.apiTokenCreationAudit(userGuid, call)

        return dbPool.useConnectionBlocking("Insert api_token") {
            val stmt = it.prepareStatement(
                "INSERT INTO api_tokens (token_hash, created_at, created_by_user_cn, created_by_user_guid, created_by_client_id) " +
                    "VALUES (?, ?, ?, ?, ?)"
            )
            stmt.setBytes(1, hashBase64String(token))
            stmt.setTimestamp(2, Timestamp.from(now))
            stmt.setString(3, username)
            stmt.setObject(4, userGuid)
            stmt.setString(5, clientId)
            stmt.executeUpdate()

            it.commit()
        }
    }

    companion object {
        const val API_TOKEN_EXPIRY_HOURS = 1L
    }
}
