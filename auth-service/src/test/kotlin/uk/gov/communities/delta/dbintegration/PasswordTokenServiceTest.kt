package uk.gov.communities.delta.dbintegration

import io.ktor.test.dispatcher.*
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.junit.BeforeClass
import org.junit.Test
import uk.gov.communities.delta.auth.services.PasswordTokenService
import uk.gov.communities.delta.auth.services.ResetPasswordTokenService
import uk.gov.communities.delta.auth.services.SetPasswordTokenService
import uk.gov.communities.delta.auth.utils.TimeSource
import uk.gov.communities.delta.helper.testServiceClient
import java.sql.Timestamp
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class PasswordTokenServiceTest {
    @Test
    fun testLookupInvalidTokenOnSetFails() = testSuspend {
        val result = setPasswordTokenService.validateToken("invalidToken", userCN)
        assertTrue(result is PasswordTokenService.NoSuchToken)
    }

    @Test
    fun testLookupInvalidTokenOnResetFails() = testSuspend {
        val result = resetPasswordTokenService.validateToken("invalidToken", userCN)
        assertTrue(result is PasswordTokenService.NoSuchToken)
    }

    @Test
    fun testLookupWrongUserOnSetFails() = testSuspend {
        val token = setPasswordTokenService.createToken(userCN)
        val result = setPasswordTokenService.validateToken(token, "not$userCN")
        assertTrue(result is PasswordTokenService.NoSuchToken)
    }

    @Test
    fun testLookupWrongUserOnResetFails() = testSuspend {
        val token = setPasswordTokenService.createToken(userCN)
        val result = resetPasswordTokenService.validateToken(token, "not$userCN")
        assertTrue(result is PasswordTokenService.NoSuchToken)
    }

    @Test
    fun testLookupCorrectUserForSetWithoutDelete() = testSuspend {
        val token = setPasswordTokenService.createToken(userCN)
        val result = setPasswordTokenService.validateToken(token, userCN)
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
        val token = setPasswordTokenService.createToken(userCN)
        var result = setPasswordTokenService.consumeTokenIfValid(token, userCN)
        assertTrue(result is PasswordTokenService.ValidToken)
        result = setPasswordTokenService.validateToken(token, userCN)
        assertTrue(result is PasswordTokenService.NoSuchToken)
    }

    @Test
    fun testLookupForResetWithDelete() = testSuspend {
        val token = resetPasswordTokenService.createToken(userCN)
        var result = resetPasswordTokenService.consumeTokenIfValid(token, userCN)
        assertTrue(result is PasswordTokenService.ValidToken)
        result = resetPasswordTokenService.validateToken(token, userCN)
        assertTrue(result is PasswordTokenService.NoSuchToken)
    }

    @Test
    fun testLookupForSetWithoutDelete() = testSuspend {
        val token = setPasswordTokenService.createToken(userCN)
        var result = setPasswordTokenService.validateToken(token, userCN)
        assertTrue(result is PasswordTokenService.ValidToken)
        result = setPasswordTokenService.validateToken(token, userCN)
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
        val originalToken = setPasswordTokenService.createToken(userCN)
        val replacementToken = setPasswordTokenService.createToken(userCN)
        var result = setPasswordTokenService.validateToken(originalToken, userCN)
        assertTrue(result is PasswordTokenService.NoSuchToken)
        result = setPasswordTokenService.consumeTokenIfValid(replacementToken, userCN)
        assertTrue(result is PasswordTokenService.ValidToken)
    }

    @Test
    fun testOnlyOneTokenPerUserForReset() = testSuspend {
        val originalToken = resetPasswordTokenService.createToken(userCN)
        val replacementToken = resetPasswordTokenService.createToken(userCN)
        var result = resetPasswordTokenService.validateToken(originalToken, userCN)
        assertTrue(result is PasswordTokenService.NoSuchToken)
        result = resetPasswordTokenService.consumeTokenIfValid(replacementToken, userCN)
        assertTrue(result is PasswordTokenService.ValidToken)
    }

    @Test
    fun testLookupExpiredTokenForSet() = testSuspend {
        val token = setPasswordTokenService.createToken(userCN)
        withContext(Dispatchers.IO) {
            testDbPool.useConnectionBlocking("Test make set password token expire") {
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
        val result = setPasswordTokenService.validateToken(token, userCN)
        assertTrue(result is PasswordTokenService.ExpiredToken)
    }

    @Test
    fun testLookupExpiredTokenForReset() = testSuspend {
        val token = resetPasswordTokenService.createToken(userCN)
        withContext(Dispatchers.IO) {
            testDbPool.useConnectionBlocking("Test make reset password token expire") {
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
        val token = setPasswordTokenService.createToken(userCN)
        assertEquals(PasswordTokenService.TOKEN_LENGTH_BYTES * 8 / 6, token.length)
    }

    @Test
    fun testTokenCreationForReset() = testSuspend {
        val token = resetPasswordTokenService.createToken(userCN)
        assertEquals(PasswordTokenService.TOKEN_LENGTH_BYTES * 8 / 6, token.length)
    }

    @Test
    fun testTablesAreIndependent() = testSuspend {
        val setToken = setPasswordTokenService.createToken(userCN)
        val resetToken = resetPasswordTokenService.createToken(userCN)
        var setTokenResult = setPasswordTokenService.validateToken(setToken, userCN)
        assertTrue(setTokenResult is PasswordTokenService.ValidToken)
        val setTokenAsResetTokenResult = resetPasswordTokenService.validateToken(setToken, userCN)
        assertEquals(PasswordTokenService.NoSuchToken, setTokenAsResetTokenResult)
        val resetTokenResult = resetPasswordTokenService.consumeTokenIfValid(resetToken, userCN)
        assertTrue(resetTokenResult is PasswordTokenService.ValidToken)
        setTokenResult = setPasswordTokenService.validateToken(setToken, userCN)
        assertTrue(setTokenResult is PasswordTokenService.ValidToken)
    }

    @Test
    fun testPasswordNeverSetChecksForSetPasswordToken() = testSuspend {
        val otherUserCN = "other" + userCN
        var passwordSet = setPasswordTokenService.passwordNeverSetForUserCN(otherUserCN)
        assertFalse(passwordSet)
        resetPasswordTokenService.createToken(otherUserCN)
        passwordSet = setPasswordTokenService.passwordNeverSetForUserCN(otherUserCN)
        assertFalse(passwordSet)
        setPasswordTokenService.createToken(otherUserCN)
        passwordSet = setPasswordTokenService.passwordNeverSetForUserCN(otherUserCN)
        assertTrue(passwordSet)
    }

    companion object {
        private val userCN = "user!example.com"
        lateinit var setPasswordTokenService: SetPasswordTokenService
        lateinit var resetPasswordTokenService: ResetPasswordTokenService
        val client = testServiceClient()

        @BeforeClass
        @JvmStatic
        fun setup() {
            setPasswordTokenService = SetPasswordTokenService(testDbPool, TimeSource.System)
            resetPasswordTokenService = ResetPasswordTokenService(testDbPool, TimeSource.System)
        }
    }
}