package uk.gov.communities.delta.auth.services

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.jetbrains.annotations.Blocking
import org.slf4j.LoggerFactory
import uk.gov.communities.delta.auth.utils.TimeSource
import java.sql.Timestamp
import java.time.Instant
import kotlin.time.Duration.Companion.hours

class RegistrationSetPasswordTokenService(private val dbPool: DbPool, timeSource: TimeSource) : PasswordTokenService("set_password_tokens", dbPool, timeSource){
    suspend fun passwordNeverSetForUserCN(userCN: String): Boolean {
        return withContext(Dispatchers.IO) {
            setPasswordTokenExistsForUserCN(userCN)
        }
    }

    @Blocking
    private fun setPasswordTokenExistsForUserCN(userCN: String): Boolean {
        dbPool.useConnection {
            val stmt = it.prepareStatement(
                "SELECT user_cn, token, created_at FROM set_password_tokens " +
                        "WHERE user_cn = ?"
            )
            stmt.setString(1, userCN)
            val result = stmt.executeQuery()
            it.commit()

            // Returns true if there is a matching entry, false if not
            return result.next()
        }
    }
}

class ResetPasswordTokenService(dbPool: DbPool, timeSource: TimeSource) : PasswordTokenService("reset_password_tokens", dbPool, timeSource)

abstract class PasswordTokenService(private val tableName: String, private val dbPool: DbPool, private val timeSource: TimeSource) {
    private val logger = LoggerFactory.getLogger(javaClass)

    sealed class TokenResult
    class ValidToken(val token: String, val userCN: String) : TokenResult()
    class ExpiredToken(val token: String, val userCN: String) : TokenResult()
    object NoSuchToken : TokenResult()

    companion object {
        val TOKEN_VALID_DURATION_SECONDS = 12.hours.inWholeSeconds
        const val TOKEN_LENGTH_BYTES = 24
    }

    suspend fun createToken(userCN: String): String {
        val token = randomBase64(TOKEN_LENGTH_BYTES)
        val now = timeSource.now()
        withContext(Dispatchers.IO) {
            insert(userCN, token, now)
        }
        return token
    }

    @Blocking
    private fun insert(userCN: String, token: String, now: Instant) {
        return dbPool.useConnection {
            val nowTimestamp = Timestamp.from(now)
            val tokenBytes = hashBase64String(token)
            val stmt = it.prepareStatement(
                "INSERT INTO $tableName (user_cn, token, created_at) VALUES (?, ?, ?) " +
                        "ON CONFLICT (user_cn) DO UPDATE SET token = ?, created_at = ?"
            )
            stmt.setString(1, userCN)
            stmt.setBytes(2, tokenBytes)
            stmt.setTimestamp(3, nowTimestamp)
            stmt.setBytes(4, tokenBytes)
            stmt.setTimestamp(5, nowTimestamp)
            stmt.executeUpdate()
            it.commit()
        }
    }

    suspend fun validateToken(token: String, userCN: String): TokenResult {
        return withContext(Dispatchers.IO) {
            readToken(token, userCN)
        }
    }

    suspend fun consumeTokenIfValid(token: String, userCN: String): TokenResult {
        return withContext(Dispatchers.IO) {
            val tokenResult = readToken(token, userCN)
            if (tokenResult is ValidToken) {
                deleteToken(token, userCN)
            }
            tokenResult
        }
    }

    @Blocking
    private fun readToken(token: String, userCN: String): TokenResult {
        dbPool.useConnection {
            val stmt = it.prepareStatement(
                "SELECT user_cn, token, created_at FROM $tableName " +
                        "WHERE token = ? AND user_cn = ?"
            )
            stmt.setBytes(1, hashBase64String(token))
            stmt.setString(2, userCN)
            val result = stmt.executeQuery()
            it.commit()
            return if (!result.next()) {
                logger.debug("No session found for token '{}' and userCN '{}'", token, userCN)
                NoSuchToken
            } else if (tokenExpired(result.getTimestamp("created_at"))) {
                ExpiredToken(token, userCN)
            } else ValidToken(token, userCN)
        }
    }

    @Blocking
    private fun deleteToken(token: String, userCN: String) {
        dbPool.useConnection {
            val stmt = it.prepareStatement(
                "DELETE FROM $tableName WHERE token = ? AND user_cn = ?",
            )
            stmt.setBytes(1, hashBase64String(token))
            stmt.setString(2, userCN)
            stmt.executeUpdate()
            it.commit()
        }
    }

    private fun tokenExpired(createdAt: Timestamp): Boolean {
        return createdAt.toInstant().plusSeconds(TOKEN_VALID_DURATION_SECONDS) < timeSource.now()
    }
}
