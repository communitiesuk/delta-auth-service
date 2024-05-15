package uk.gov.communities.delta.auth.services

import org.jetbrains.annotations.Blocking
import org.slf4j.LoggerFactory
import uk.gov.communities.delta.auth.repositories.DbPool
import uk.gov.communities.delta.auth.repositories.LdapUser
import uk.gov.communities.delta.auth.repositories.map
import uk.gov.communities.delta.auth.saml.SAMLTokenService
import uk.gov.communities.delta.auth.utils.TimeSource
import uk.gov.communities.delta.auth.utils.hashBase64String
import uk.gov.communities.delta.auth.utils.randomBase64
import java.nio.ByteBuffer
import java.security.SecureRandom
import java.sql.Timestamp
import java.time.Instant
import java.time.temporal.ChronoUnit
import java.util.*

class DeltaApiTokenService(
    private val dbPool: DbPool,
    private val timeSource: TimeSource
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
                result.getString("client_secret") == secret
            }
        }
    }

    fun createAndStoreApiToken(username: String, clientId: String): String {
        logger.atInfo().addKeyValue("clientId", clientId).log("Creating new API token for client")
        val apiToken = randomBase64(32)
        insertApiToken(apiToken, timeSource.now(), username, clientId)
        return apiToken
    }

    suspend fun validateApiToken(apiToken: String): String? {
        return dbPool.useConnectionNonBlocking("Validate client id and secret") {
            val stmt = it.prepareStatement(
                "SELECT created_at, created_by_user_cn, created_by_client_id FROM api_tokens " +
                    "WHERE token_hash = ? AND created_at > ?"
            )
            stmt.setBytes(1, hashBase64String(apiToken))
            val earliestValidCreationTime = timeSource.now().plus(-API_TOKEN_EXPIRY_HOURS, ChronoUnit.HOURS)
            stmt.setTimestamp(2, Timestamp.from(earliestValidCreationTime))
            val result = stmt.executeQuery()
            if (!result.next()) {
                null
            } else {
                result.getString("created_by_user_cn")
            }
        }
    }

    @Blocking
    private fun insertApiToken(token: String, now: Instant, username: String, clientId: String) {
        return dbPool.useConnectionBlocking("Insert api_token") {
            val stmt = it.prepareStatement(
                "INSERT INTO api_tokens (token_hash, created_at, created_by_user_cn, created_by_client_id) " +
                    "VALUES (?, ?, ?, ?)"
            )
            stmt.setBytes(1, hashBase64String(token))
            stmt.setTimestamp(2, Timestamp.from(now))
            stmt.setString(3, username)
            stmt.setString(4, clientId)
            stmt.executeUpdate()
            it.commit()
        }
    }

    companion object {
        const val API_TOKEN_EXPIRY_HOURS = 1L
    }
}
