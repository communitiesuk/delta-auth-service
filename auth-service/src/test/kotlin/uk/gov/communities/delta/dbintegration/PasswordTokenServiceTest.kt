package uk.gov.communities.delta.dbintegration

import io.ktor.test.dispatcher.*
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.junit.BeforeClass
import org.junit.Test
import uk.gov.communities.delta.auth.services.PasswordTokenService
import uk.gov.communities.delta.auth.services.RegistrationSetPasswordTokenService
import uk.gov.communities.delta.auth.services.ResetPasswordTokenService
import uk.gov.communities.delta.auth.utils.TimeSource
import uk.gov.communities.delta.helper.testServiceClient
import java.sql.Timestamp
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class PasswordTokenServiceTest {
    @Test
    fun testLookupInvalidTokenOnSetFails() = testSuspend {
        val result = registrationSetPasswordTokenService.validateToken("invalidToken", userCN)
        assertTrue(result is PasswordTokenService.NoSuchToken)
    }

    @Test
    fun testLookupInvalidTokenOnResetFails() = testSuspend {
        val result = resetPasswordTokenService.validateToken("invalidToken", userCN)
        assertTrue(result is PasswordTokenService.NoSuchToken)
    }

    @Test
    fun testLookupWrongUserOnSetFails() = testSuspend {
        val token = registrationSetPasswordTokenService.createToken(userCN)
        val result = registrationSetPasswordTokenService.validateToken(token, "not$userCN")
        assertTrue(result is PasswordTokenService.NoSuchToken)
    }

    @Test
    fun testLookupWrongUserOnResetFails() = testSuspend {
        val token = registrationSetPasswordTokenService.createToken(userCN)
        val result = resetPasswordTokenService.validateToken(token, "not$userCN")
        assertTrue(result is PasswordTokenService.NoSuchToken)
    }

    @Test
    fun testLookupCorrectUserForSetWithoutDelete() = testSuspend {
        val token = registrationSetPasswordTokenService.createToken(userCN)
        val result = registrationSetPasswordTokenService.validateToken(token, userCN)
        assertTrue(result is PasswordTokenService.ValidToken)
    }

    @Test
    fun testLookupCorrectUserForResetWithoutDelete() = testSuspend {
        val token = resetPasswordTokenService.createToken(userCN)
        val result = resetPasswordTokenService.validateToken(token, userCN)
        assertTrue(result is PasswordTokenService.ValidToken)
    }

    @Test
    fun testLookupForSetWithDelete() = testSuspend {
        val token = registrationSetPasswordTokenService.createToken(userCN)
        var result = registrationSetPasswordTokenService.consumeToken(token, userCN)
        assertTrue(result is PasswordTokenService.ValidToken)
        result = registrationSetPasswordTokenService.validateToken(token, userCN)
        assertTrue(result is PasswordTokenService.NoSuchToken)
    }

    @Test
    fun testLookupForResetWithDelete() = testSuspend {
        val token = resetPasswordTokenService.createToken(userCN)
        var result = resetPasswordTokenService.consumeToken(token, userCN)
        assertTrue(result is PasswordTokenService.ValidToken)
        result = resetPasswordTokenService.validateToken(token, userCN)
        assertTrue(result is PasswordTokenService.NoSuchToken)
    }

    @Test
    fun testLookupForSetWithoutDelete() = testSuspend {
        val token = registrationSetPasswordTokenService.createToken(userCN)
        var result = registrationSetPasswordTokenService.validateToken(token, userCN)
        assertTrue(result is PasswordTokenService.ValidToken)
        result = registrationSetPasswordTokenService.validateToken(token, userCN)
        assertTrue(result is PasswordTokenService.ValidToken)
    }

    @Test
    fun testLookupForResetWithoutDelete() = testSuspend {
        val token = resetPasswordTokenService.createToken(userCN)
        var result = resetPasswordTokenService.validateToken(token, userCN)
        assertTrue(result is PasswordTokenService.ValidToken)
        result = resetPasswordTokenService.validateToken(token, userCN)
        assertTrue(result is PasswordTokenService.ValidToken)
    }

    @Test
    fun testOnlyOneTokenPerUserForSet() = testSuspend {
        val originalToken = registrationSetPasswordTokenService.createToken(userCN)
        val replacementToken = registrationSetPasswordTokenService.createToken(userCN)
        var result = registrationSetPasswordTokenService.validateToken(originalToken, userCN)
        assertTrue(result is PasswordTokenService.NoSuchToken)
        result = registrationSetPasswordTokenService.consumeToken(replacementToken, userCN)
        assertTrue(result is PasswordTokenService.ValidToken)
    }

    @Test
    fun testOnlyOneTokenPerUserForReset() = testSuspend {
        val originalToken = resetPasswordTokenService.createToken(userCN)
        val replacementToken = resetPasswordTokenService.createToken(userCN)
        var result = resetPasswordTokenService.validateToken(originalToken, userCN)
        assertTrue(result is PasswordTokenService.NoSuchToken)
        result = resetPasswordTokenService.consumeToken(replacementToken, userCN)
        assertTrue(result is PasswordTokenService.ValidToken)
    }

    @Test
    fun testLookupExpiredTokenForSet() = testSuspend {
        val token = registrationSetPasswordTokenService.createToken(userCN)
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
        val result = registrationSetPasswordTokenService.validateToken(token, userCN)
        assertTrue(result is PasswordTokenService.ExpiredToken)
    }

    @Test
    fun testLookupExpiredTokenForReset() = testSuspend {
        val token = resetPasswordTokenService.createToken(userCN)
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
        val result = resetPasswordTokenService.validateToken(token, userCN)
        assertTrue(result is PasswordTokenService.ExpiredToken)
    }

    @Test
    fun testTokenCreationForSet() = testSuspend {
        val token = registrationSetPasswordTokenService.createToken(userCN)
        assertEquals(PasswordTokenService.TOKEN_LENGTH_BYTES * 8 / 6, token.length)
    }

    @Test
    fun testTokenCreationForReset() = testSuspend {
        val token = resetPasswordTokenService.createToken(userCN)
        assertEquals(PasswordTokenService.TOKEN_LENGTH_BYTES * 8 / 6, token.length)
    }

    @Test
    fun testTablesAreIndependent() = testSuspend {
        val setToken = registrationSetPasswordTokenService.createToken(userCN)
        val resetToken = resetPasswordTokenService.createToken(userCN)
        var setTokenResult = registrationSetPasswordTokenService.validateToken(setToken, userCN)
        assertTrue(setTokenResult is PasswordTokenService.ValidToken)
        val setTokenAsResetTokenResult = resetPasswordTokenService.validateToken(setToken, userCN)
        assertEquals(PasswordTokenService.NoSuchToken, setTokenAsResetTokenResult)
        val resetTokenResult = resetPasswordTokenService.consumeToken(resetToken, userCN)
        assertTrue(resetTokenResult is PasswordTokenService.ValidToken)
        setTokenResult = registrationSetPasswordTokenService.validateToken(setToken, userCN)
        assertTrue(setTokenResult is PasswordTokenService.ValidToken)
    }

    @Test
    fun testPasswordNeverSetChecksForSetPasswordToken() = testSuspend {
        val otherUserCN = "other" + userCN
        var passwordSet = registrationSetPasswordTokenService.passwordNeverSetForUserCN(otherUserCN)
        assertFalse(passwordSet)
        resetPasswordTokenService.createToken(otherUserCN)
        passwordSet = registrationSetPasswordTokenService.passwordNeverSetForUserCN(otherUserCN)
        assertFalse(passwordSet)
        registrationSetPasswordTokenService.createToken(otherUserCN)
        passwordSet = registrationSetPasswordTokenService.passwordNeverSetForUserCN(otherUserCN)
        assertTrue(passwordSet)
    }

    companion object {
        private val userCN = "user!example.com"
        lateinit var registrationSetPasswordTokenService: RegistrationSetPasswordTokenService
        lateinit var resetPasswordTokenService: ResetPasswordTokenService
        val client = testServiceClient()

        @BeforeClass
        @JvmStatic
        fun setup() {
            registrationSetPasswordTokenService = RegistrationSetPasswordTokenService(testDbPool, TimeSource.System)
            resetPasswordTokenService = ResetPasswordTokenService(testDbPool, TimeSource.System)
        }
    }
}