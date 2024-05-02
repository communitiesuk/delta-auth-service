package uk.gov.communities.delta.auth.services

import org.jetbrains.annotations.Blocking
import org.slf4j.LoggerFactory
import uk.gov.communities.delta.auth.repositories.DbPool
import uk.gov.communities.delta.auth.repositories.map
import uk.gov.communities.delta.auth.saml.SAMLTokenService
import uk.gov.communities.delta.auth.utils.TimeSource
import uk.gov.communities.delta.auth.utils.hashBase64String
import java.sql.Timestamp
import java.time.Instant
import java.time.temporal.ChronoUnit

// TODO 836 add logging
class DeltaApiTokenService(
    private val dbPool: DbPool,
    private val samlTokenService: SAMLTokenService,
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
        // validate username and password and client stuff in controller
        val apiToken = generateApiToken()
        // store token
        insertApiToken(apiToken, timeSource.now(), username, clientId)
        // return token
        return apiToken
    }

    suspend fun validateApiToken(apiToken: String): Boolean {
        return dbPool.useConnectionNonBlocking("Validate client id and secret") {
            val stmt = it.prepareStatement(
                "SELECT created_at, created_by_user, created_by_client FROM api_tokens " +
                    "WHERE token_hash = ?"
            )
            stmt.setBytes(1, hashBase64String(apiToken))
            val result = stmt.executeQuery()
            if (!result.next()) {
                false
            } else {
                val now = timeSource.now()
                result.getTime("created_at").toInstant().plus(API_TOKEN_EXPIRY_HOURS, ChronoUnit.HOURS) > now
            }
        }
    }

    fun getApiSamlToken(): String {
        throw NotImplementedError()
    }

    private fun generateApiToken(): String {
        // TODO 836 do we need a special approach here?
        val characters = ('A'..'Z') + ('a'..'z') + ('0'..'9')
        return (1..32).map { characters.random() }.joinToString("")
    }

    @Blocking
    private fun insertApiToken(token: String, now: Instant, username: String, clientId: String) {
        return dbPool.useConnectionBlocking("Insert api_token") {
            val stmt = it.prepareStatement(
                "INSERT INTO delta_session (token_hash, created_at, created_by_user, created_by_client) " +
                    "VALUES (?, ?, ?, ?)"
            )
            stmt.setBytes(1, hashBase64String(token))
            stmt.setTimestamp(2, Timestamp.from(now))
            stmt.setString(3, username)
            stmt.setString(4, clientId)
            stmt.executeQuery() // TODO 836 do we need any checking for errors? does this do that?
            it.commit()
        }
    }

    companion object {
        const val API_TOKEN_EXPIRY_HOURS = 1L
    }
}
