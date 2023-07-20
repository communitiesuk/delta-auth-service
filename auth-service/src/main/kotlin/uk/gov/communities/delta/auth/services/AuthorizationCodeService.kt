package uk.gov.communities.delta.auth.services

import net.logstash.logback.argument.StructuredArguments
import org.slf4j.LoggerFactory
import java.security.SecureRandom
import java.sql.Timestamp
import java.time.Instant
import java.util.concurrent.ConcurrentHashMap
import kotlin.io.encoding.Base64
import kotlin.io.encoding.ExperimentalEncodingApi

interface IAuthorizationCodeService {
    fun generateAndStore(userCn: String): String
    fun lookupAndInvalidate(code: String): AuthCode?
}

// Assume we only have one client (delta-website)
data class AuthCode(val code: String, val userCn: String, val createdAt: Instant) {
    fun expired() = createdAt.plusSeconds(AuthorizationCodeService.AUTH_CODE_VALID_DURATION_SECONDS) < Instant.now()
}

class AuthorizationCodeService(private val dbPool: DbPool) : IAuthorizationCodeService {
    // TODO Should be stored in a database, and expired ones automatically deleted
    private val authCodes = ConcurrentHashMap<String, AuthCode>()
    private val sr: SecureRandom by lazy { SecureRandom() }
    private val logger = LoggerFactory.getLogger(javaClass)

    companion object {
        const val AUTH_CODE_VALID_DURATION_SECONDS = 30L
        const val AUTH_CODE_LENGTH_BYTES = 24
    }

    override fun generateAndStore(userCn: String): String {
        val code = randomBase64()
        val now = Instant.now()
        val authCode = AuthCode(code, userCn, now)
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

    @OptIn(ExperimentalEncodingApi::class)
    private fun randomBase64(): String {
        val bytes = ByteArray(AUTH_CODE_LENGTH_BYTES)
        sr.nextBytes(bytes)
        return Base64.UrlSafe.encode(bytes)
    }

    private fun insert(authCode: AuthCode) {
        dbPool.connection().use {
            val stmt = it.prepareStatement(
                "INSERT INTO authorization_codes (username, code, created_at) " +
                        "VALUES (?, ?, ?)"
            )
            stmt.setString(1, authCode.userCn)
            stmt.setString(2, authCode.code)
            stmt.setTimestamp(3, Timestamp.from(authCode.createdAt))
            stmt.executeUpdate()
            it.commit()
        }
    }

    private fun deleteReturning(code: String): AuthCode? {
        dbPool.connection().use {
            val stmt = it.prepareStatement(
                "DELETE FROM authorization_codes " +
                        "WHERE code = ? RETURNING username, created_at"
            )
            stmt.setString(1, code)
            val resultSet = stmt.executeQuery()
            if (!resultSet.next()) {
                logger.debug("Code not found {}", code)
                return null
            }
            val authCode = AuthCode(
                code,
                resultSet.getString(1),
                resultSet.getTimestamp(2).toInstant()
            )
            it.commit()
            return authCode
        }
    }
}
