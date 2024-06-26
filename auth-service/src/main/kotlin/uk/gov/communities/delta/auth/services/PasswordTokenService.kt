@file:Suppress("SqlSourceToSinkFlow", "SqlResolve")

package uk.gov.communities.delta.auth.services

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.jetbrains.annotations.Blocking
import org.slf4j.LoggerFactory
import uk.gov.communities.delta.auth.repositories.DbPool
import uk.gov.communities.delta.auth.utils.TimeSource
import uk.gov.communities.delta.auth.utils.hashBase64String
import uk.gov.communities.delta.auth.utils.randomBase64
import java.sql.Timestamp
import java.time.Instant
import java.util.*
import kotlin.time.Duration.Companion.hours

// Set Password tokens are used for users where their account needs enabling upon password being set:
//  - first time users
//  - accounts that had been disabled (via email sent by an admin)
class SetPasswordTokenService(private val dbPool: DbPool, timeSource: TimeSource) :
    PasswordTokenService(dbPool, timeSource) {
    override val tableName: String = "set_password_tokens"
    suspend fun passwordNeverSetForUserCN(userGUID: UUID): Boolean {
        return withContext(Dispatchers.IO) {
            setPasswordTokenExistsForUserCN(userGUID)
        }
    }

    suspend fun clearTokenForUserGUID(userGUID: UUID) {
        withContext(Dispatchers.IO) {
            if (deleteForUser(userGUID)) logger.info("Cleared set password token for user {}", userGUID)
        }
    }

    @Blocking
    private fun deleteForUser(userGUID: UUID): Boolean {
        return dbPool.useConnectionBlocking("Delete token for user") {
            val stmt = it.prepareStatement(
                "DELETE FROM $tableName WHERE user_guid = ?"
            )
            stmt.setObject(1, userGUID)
            val result = stmt.executeUpdate()
            it.commit()
            result == 1
        }
    }

    @Blocking
    private fun setPasswordTokenExistsForUserCN(userGUID: UUID): Boolean {
        return dbPool.useConnectionBlocking("Check if set password token exists") {
            val stmt = it.prepareStatement(
                "SELECT token, created_at FROM $tableName " +
                    "WHERE user_guid = ?"
            )
            stmt.setObject(1, userGUID)
            val result = stmt.executeQuery()

            // Returns true if there is a matching entry, false if not
            result.next()
        }
    }
}

class ResetPasswordTokenService(dbPool: DbPool, timeSource: TimeSource) : PasswordTokenService(dbPool, timeSource) {
    override val tableName: String = "reset_password_tokens"
}

abstract class PasswordTokenService(private val dbPool: DbPool, private val timeSource: TimeSource) {
    protected val logger = LoggerFactory.getLogger(javaClass)
    protected abstract val tableName: String

    sealed class TokenResult
    class ValidToken(val token: String, val userGUID: UUID) : TokenResult()
    class ExpiredToken(val token: String, val userGUID: UUID) : TokenResult()
    data object NoSuchToken : TokenResult()

    companion object {
        val TOKEN_VALID_DURATION_SECONDS = 12.hours.inWholeSeconds
        const val TOKEN_LENGTH_BYTES = 24
    }

    suspend fun createToken(userGUID: UUID): String {
        val token = randomBase64(TOKEN_LENGTH_BYTES)
        val now = timeSource.now()
        withContext(Dispatchers.IO) {
            insert(userGUID, token, now)
        }
        return token
    }

    @Blocking
    private fun insert(userGUID: UUID, token: String, now: Instant) {
        return dbPool.useConnectionBlocking("Insert password token") {
            val nowTimestamp = Timestamp.from(now)
            val tokenBytes = hashBase64String(token)
            val stmt = it.prepareStatement(
                "INSERT INTO $tableName (user_guid, token, created_at) VALUES (?, ?, ?) " +
                    "ON CONFLICT (user_guid) DO UPDATE SET token = ?, created_at = ?"
            )
            stmt.setObject(1, userGUID)
            stmt.setBytes(2, tokenBytes)
            stmt.setTimestamp(3, nowTimestamp)
            stmt.setBytes(4, tokenBytes)
            stmt.setTimestamp(5, nowTimestamp)
            stmt.executeUpdate()
            it.commit()
        }
    }

    suspend fun validateToken(token: String, userGUID: UUID): TokenResult {
        return withContext(Dispatchers.IO) {
            readToken(token, userGUID)
        }
    }

    suspend fun consumeTokenIfValid(token: String, userGUID: UUID): TokenResult {
        return withContext(Dispatchers.IO) {
            var tokenResult = readToken(token, userGUID)
            if (tokenResult is ValidToken) {
                val tokenDeletedSuccessfully = deleteToken(token, userGUID)
                if (!tokenDeletedSuccessfully) {
                    tokenResult = NoSuchToken
                    logger.warn("Token not deleted successfully")
                }
            }
            tokenResult
        }
    }

    @Blocking
    private fun readToken(token: String, userGUID: UUID): TokenResult {
        return dbPool.useConnectionBlocking("Read select password token") {
            val stmt = it.prepareStatement(
                "SELECT token, created_at FROM $tableName " +
                    "WHERE token = ? AND user_guid = ?"
            )
            stmt.setBytes(1, hashBase64String(token))
            stmt.setObject(2, userGUID)
            val result = stmt.executeQuery()
            return@useConnectionBlocking if (!result.next()) {
                logger.debug("No session found for token '{}' and userCN '{}'", token, userGUID)
                NoSuchToken
            } else if (tokenExpired(result.getTimestamp("created_at"))) {
                ExpiredToken(token, userGUID)
            } else ValidToken(token, userGUID)
        }
    }

    @Blocking
    private fun deleteToken(token: String, userGUID: UUID): Boolean {
        return dbPool.useConnectionBlocking("Delete token") {
            val stmt = it.prepareStatement(
                "DELETE FROM $tableName WHERE token = ? AND user_guid = ?",
            )
            stmt.setBytes(1, hashBase64String(token))
            stmt.setObject(2, userGUID)
            val result = stmt.executeUpdate()
            it.commit()
            result == 1
        }
    }

    private fun tokenExpired(createdAt: Timestamp): Boolean {
        return createdAt.toInstant().plusSeconds(TOKEN_VALID_DURATION_SECONDS) < timeSource.now()
    }
}
