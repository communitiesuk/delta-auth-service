package uk.gov.communities.delta.auth.services

import net.logstash.logback.argument.StructuredArguments
import org.slf4j.LoggerFactory
import java.security.SecureRandom
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

class AuthorizationCodeService : IAuthorizationCodeService {
    // TODO Should be stored in a database, and expired ones automatically deleted
    private val authCodes = ConcurrentHashMap<String, AuthCode>()
    private val sr = SecureRandom()
    private val logger = LoggerFactory.getLogger(javaClass)

    companion object {
        const val AUTH_CODE_VALID_DURATION_SECONDS = 30L
        const val AUTH_CODE_LENGTH_BYTES = 24
    }

    override fun generateAndStore(userCn: String): String {
        val code = randomBase64()
        val now = Instant.now()
        val authCode = AuthCode(code, userCn, now)

        authCodes[code] = authCode

        logger.info("Generated auth code for user {} at {}", StructuredArguments.keyValue("username", userCn), now)
        return code
    }

    @OptIn(ExperimentalEncodingApi::class)
    private fun randomBase64(): String {
        val bytes = ByteArray(AUTH_CODE_LENGTH_BYTES)
        sr.nextBytes(bytes)
        return Base64.UrlSafe.encode(bytes)
    }

    override fun lookupAndInvalidate(code: String): AuthCode? {
        val entry = authCodes.remove(code) ?: return null
        if (entry.expired()) {
            logger.warn("Expired auth code {} for user {}", code, entry.userCn)
            return null
        }
        return entry
    }
}
