package uk.gov.communities.delta.dbintegration

import io.ktor.test.dispatcher.*
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.junit.BeforeClass
import org.junit.Test
import uk.gov.communities.delta.auth.services.PasswordTokenService
import uk.gov.communities.delta.auth.utils.TimeSource
import uk.gov.communities.delta.helper.testServiceClient
import java.sql.Timestamp
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class PasswordTokenServiceTest {
    @Test
    fun testLookupInvalidTokenOnSetFails() = testSuspend {
        val result = service.validateToken("invalidToken", userCN, true)
        assertTrue(result is PasswordTokenService.NoSuchToken)
    }

    @Test
    fun testLookupInvalidTokenOnResetFails() = testSuspend {
        val result = service.validateToken("invalidToken", userCN, false)
        assertTrue(result is PasswordTokenService.NoSuchToken)
    }

    @Test
    fun testLookupWrongUserOnSetFails() = testSuspend {
        val token = service.createToken(userCN, true)
        val result = service.validateToken(token, "not$userCN", true)
        assertTrue(result is PasswordTokenService.NoSuchToken)
    }

    @Test
    fun testLookupWrongUserOnResetFails() = testSuspend {
        val token = service.createToken(userCN, true)
        val result = service.validateToken(token, "not$userCN", false)
        assertTrue(result is PasswordTokenService.NoSuchToken)
    }

    @Test
    fun testLookupCorrectUserForSetWithoutDelete() = testSuspend {
        val token = service.createToken(userCN, true)
        val result = service.validateToken(token, userCN, true)
        assertTrue(result is PasswordTokenService.ValidToken)
    }

    @Test
    fun testLookupCorrectUserForResetWithoutDelete() = testSuspend {
        val token = service.createToken(userCN, false)
        val result = service.validateToken(token, userCN, false)
        assertTrue(result is PasswordTokenService.ValidToken)
    }

    @Test
    fun testLookupForSetWithDelete() = testSuspend {
        val token = service.createToken(userCN, true)
        var result = service.consumeToken(token, userCN, true)
        assertTrue(result is PasswordTokenService.ValidToken)
        result = service.validateToken(token, userCN, true)
        assertTrue(result is PasswordTokenService.NoSuchToken)
    }

    @Test
    fun testLookupForResetWithDelete() = testSuspend {
        val token = service.createToken(userCN, false)
        var result = service.consumeToken(token, userCN, false)
        assertTrue(result is PasswordTokenService.ValidToken)
        result = service.validateToken(token, userCN, false)
        assertTrue(result is PasswordTokenService.NoSuchToken)
    }

    @Test
    fun testLookupForSetWithoutDelete() = testSuspend {
        val token = service.createToken(userCN, true)
        var result = service.validateToken(token, userCN, true)
        assertTrue(result is PasswordTokenService.ValidToken)
        result = service.validateToken(token, userCN, true)
        assertTrue(result is PasswordTokenService.ValidToken)
    }

    @Test
    fun testLookupForResetWithoutDelete() = testSuspend {
        val token = service.createToken(userCN, false)
        var result = service.validateToken(token, userCN, false)
        assertTrue(result is PasswordTokenService.ValidToken)
        result = service.validateToken(token, userCN, false)
        assertTrue(result is PasswordTokenService.ValidToken)
    }

    @Test
    fun testOnlyOneTokenPerUserForSet() = testSuspend {
        val originalToken = service.createToken(userCN, true)
        val replacementToken = service.createToken(userCN, true)
        var result = service.validateToken(originalToken, userCN, true)
        assertTrue(result is PasswordTokenService.NoSuchToken)
        result = service.consumeToken(replacementToken, userCN, true)
        assertTrue(result is PasswordTokenService.ValidToken)
    }

    @Test
    fun testOnlyOneTokenPerUserForReset() = testSuspend {
        val originalToken = service.createToken(userCN, false)
        val replacementToken = service.createToken(userCN, false)
        var result = service.validateToken(originalToken, userCN, false)
        assertTrue(result is PasswordTokenService.NoSuchToken)
        result = service.consumeToken(replacementToken, userCN, false)
        assertTrue(result is PasswordTokenService.ValidToken)
    }

    @Test
    fun testLookupExpiredTokenForSet() = testSuspend {
        val token = service.createToken(userCN, true)
        withContext(Dispatchers.IO) {
            testDbPool.useConnection {
                val stmt = it.prepareStatement(
                    "UPDATE set_password_tokens SET created_at = ? WHERE user_cn = ? "
                )
                stmt.setTimestamp(
                    1,
                    Timestamp.from(
                        TimeSource.System.now().minusSeconds(PasswordTokenService.TOKEN_VALID_DURATION_SECONDS)
                    )
                )
                stmt.setString(2, userCN)
                stmt.executeUpdate()
                it.commit()
            }
        }
        val result = service.validateToken(token, userCN, true)
        assertTrue(result is PasswordTokenService.ExpiredToken)
    }

    @Test
    fun testLookupExpiredTokenForReset() = testSuspend {
        val token = service.createToken(userCN, false)
        withContext(Dispatchers.IO) {
            testDbPool.useConnection {
                val stmt = it.prepareStatement(
                    "UPDATE reset_password_tokens SET created_at = ? WHERE user_cn = ? "
                )
                stmt.setTimestamp(
                    1,
                    Timestamp.from(
                        TimeSource.System.now().minusSeconds(PasswordTokenService.TOKEN_VALID_DURATION_SECONDS)
                    )
                )
                stmt.setString(2, userCN)
                stmt.executeUpdate()
                it.commit()
            }
        }
        val result = service.validateToken(token, userCN, false)
        assertTrue(result is PasswordTokenService.ExpiredToken)
    }

    @Test
    fun testTokenCreationForSet() = testSuspend {
        val token = service.createToken(userCN, true)
        assertEquals(PasswordTokenService.TOKEN_LENGTH_BYTES * 8 / 6, token.length)
    }

    @Test
    fun testTokenCreationForReset() = testSuspend {
        val token = service.createToken(userCN, false)
        assertEquals(PasswordTokenService.TOKEN_LENGTH_BYTES * 8 / 6, token.length)
    }

    @Test
    fun testTablesAreIndependent() = testSuspend {
        val setToken = service.createToken(userCN, true)
        val resetToken = service.createToken(userCN, false)
        var setTokenResult = service.validateToken(setToken, userCN, true)
        assertTrue(setTokenResult is PasswordTokenService.ValidToken)
        val setTokenAsResetTokenResult = service.validateToken(setToken, userCN, false)
        assertEquals(PasswordTokenService.NoSuchToken, setTokenAsResetTokenResult)
        val resetTokenResult = service.consumeToken(resetToken, userCN, false)
        assertTrue(resetTokenResult is PasswordTokenService.ValidToken)
        setTokenResult = service.validateToken(setToken, userCN, true)
        assertTrue(setTokenResult is PasswordTokenService.ValidToken)
    }

    @Test
    fun testPasswordNeverSetChecksForSetPasswordToken() = testSuspend {
        val otherUserCN = "other" + userCN
        var passwordSet = service.passwordNeverSetForUserCN(otherUserCN)
        assertFalse(passwordSet)
        service.createToken(otherUserCN, false)
        passwordSet = service.passwordNeverSetForUserCN(otherUserCN)
        assertFalse(passwordSet)
        service.createToken(otherUserCN, true)
        passwordSet = service.passwordNeverSetForUserCN(otherUserCN)
        assertTrue(passwordSet)
    }

    companion object {
        private val userCN = "user!example.com"
        lateinit var service: PasswordTokenService
        val client = testServiceClient()

        @BeforeClass
        @JvmStatic
        fun setup() {
            service = PasswordTokenService(testDbPool, TimeSource.System)
        }
    }
}