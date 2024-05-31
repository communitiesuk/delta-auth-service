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
import java.util.*
import kotlin.test.*

class PasswordTokenServiceTest {
    @Test
    fun testLookupInvalidTokenOnSetFails() = testSuspend {
        val result = setPasswordTokenService.validateToken("invalidToken", userCN, userGUID)
        assertTrue(result is PasswordTokenService.NoSuchToken)
    }

    @Test
    fun testLookupInvalidTokenOnResetFails() = testSuspend {
        val result = resetPasswordTokenService.validateToken("invalidToken", userCN, userGUID)
        assertTrue(result is PasswordTokenService.NoSuchToken)
    }

    @Test
    fun testLookupWrongUserOnSetFails() = testSuspend {
        val token = setPasswordTokenService.createToken(userCN, userGUID)
        val result = setPasswordTokenService.validateToken(token, "not$userCN", UUID.randomUUID())
        assertTrue(result is PasswordTokenService.NoSuchToken)
    }

    @Test
    fun testLookupWrongUserOnResetFails() = testSuspend {
        val token = setPasswordTokenService.createToken(userCN, userGUID)
        val result = resetPasswordTokenService.validateToken(token, "not$userCN", UUID.randomUUID())
        assertTrue(result is PasswordTokenService.NoSuchToken)
    }

    @Test
    fun testLookupCorrectUserForSetWithoutDelete() = testSuspend {
        val token = setPasswordTokenService.createToken(userCN, userGUID)
        val result = setPasswordTokenService.validateToken(token, userCN, userGUID)
        assertTrue(result is PasswordTokenService.ValidToken)
    }

    @Test
    fun testLookupCorrectUserForResetWithoutDelete() = testSuspend {
        val token = resetPasswordTokenService.createToken(userCN, userGUID)
        val result = resetPasswordTokenService.validateToken(token, userCN, userGUID)
        assertTrue(result is PasswordTokenService.ValidToken)
    }

    @Test
    fun testLookupForSetWithDelete() = testSuspend {
        val token = setPasswordTokenService.createToken(userCN, userGUID)
        var result = setPasswordTokenService.consumeTokenIfValid(token, userCN, userGUID)
        assertTrue(result is PasswordTokenService.ValidToken)
        result = setPasswordTokenService.validateToken(token, userCN, userGUID)
        assertTrue(result is PasswordTokenService.NoSuchToken)
    }

    @Test
    fun testLookupForResetWithDelete() = testSuspend {
        val token = resetPasswordTokenService.createToken(userCN, userGUID)
        var result = resetPasswordTokenService.consumeTokenIfValid(token, userCN, userGUID)
        assertTrue(result is PasswordTokenService.ValidToken)
        result = resetPasswordTokenService.validateToken(token, userCN, userGUID)
        assertTrue(result is PasswordTokenService.NoSuchToken)
    }

    @Test
    fun testLookupForSetWithoutDelete() = testSuspend {
        val token = setPasswordTokenService.createToken(userCN, userGUID)
        var result = setPasswordTokenService.validateToken(token, userCN, userGUID)
        assertTrue(result is PasswordTokenService.ValidToken)
        result = setPasswordTokenService.validateToken(token, userCN, userGUID)
        assertTrue(result is PasswordTokenService.ValidToken)
    }

    @Test
    fun testLookupForResetWithoutDelete() = testSuspend {
        val token = resetPasswordTokenService.createToken(userCN, userGUID)
        var result = resetPasswordTokenService.validateToken(token, userCN, userGUID)
        assertTrue(result is PasswordTokenService.ValidToken)
        result = resetPasswordTokenService.validateToken(token, userCN, userGUID)
        assertTrue(result is PasswordTokenService.ValidToken)
    }

    @Test
    fun testOnlyOneTokenPerUserForSet() = testSuspend {
        val originalToken = setPasswordTokenService.createToken(userCN, userGUID)
        val replacementToken = setPasswordTokenService.createToken(userCN, userGUID)
        var result = setPasswordTokenService.validateToken(originalToken, userCN, userGUID)
        assertTrue(result is PasswordTokenService.NoSuchToken)
        result = setPasswordTokenService.consumeTokenIfValid(replacementToken, userCN, userGUID)
        assertTrue(result is PasswordTokenService.ValidToken)
    }

    @Test
    fun testOnlyOneTokenPerUserForReset() = testSuspend {
        val originalToken = resetPasswordTokenService.createToken(userCN, userGUID)
        val replacementToken = resetPasswordTokenService.createToken(userCN, userGUID)
        var result = resetPasswordTokenService.validateToken(originalToken, userCN, userGUID)
        assertTrue(result is PasswordTokenService.NoSuchToken)
        result = resetPasswordTokenService.consumeTokenIfValid(replacementToken, userCN, userGUID)
        assertTrue(result is PasswordTokenService.ValidToken)
    }

    @Test
    fun testLookupExpiredTokenForSet() = testSuspend {
        val token = setPasswordTokenService.createToken(userCN, userGUID)
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
        val result = setPasswordTokenService.validateToken(token, userCN, userGUID)
        assertTrue(result is PasswordTokenService.ExpiredToken)
    }

    @Test
    fun testLookupExpiredTokenForReset() = testSuspend {
        val token = resetPasswordTokenService.createToken(userCN, userGUID)
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
        val result = resetPasswordTokenService.validateToken(token, userCN, userGUID)
        assertTrue(result is PasswordTokenService.ExpiredToken)
    }

    @Test
    fun testTokenCreationForSet() = testSuspend {
        val token = setPasswordTokenService.createToken(userCN, userGUID)
        assertEquals(PasswordTokenService.TOKEN_LENGTH_BYTES * 8 / 6, token.length)
    }

    @Test
    fun testTokenCreationForReset() = testSuspend {
        val token = resetPasswordTokenService.createToken(userCN, userGUID)
        assertEquals(PasswordTokenService.TOKEN_LENGTH_BYTES * 8 / 6, token.length)
    }

    @Test
    fun testTablesAreIndependent() = testSuspend {
        val setToken = setPasswordTokenService.createToken(userCN, userGUID)
        val resetToken = resetPasswordTokenService.createToken(userCN, userGUID)
        var setTokenResult = setPasswordTokenService.validateToken(setToken, userCN, userGUID)
        assertTrue(setTokenResult is PasswordTokenService.ValidToken)
        val setTokenAsResetTokenResult = resetPasswordTokenService.validateToken(setToken, userCN, userGUID)
        assertEquals(PasswordTokenService.NoSuchToken, setTokenAsResetTokenResult)
        val resetTokenResult = resetPasswordTokenService.consumeTokenIfValid(resetToken, userCN, userGUID)
        assertTrue(resetTokenResult is PasswordTokenService.ValidToken)
        setTokenResult = setPasswordTokenService.validateToken(setToken, userCN, userGUID)
        assertTrue(setTokenResult is PasswordTokenService.ValidToken)
    }

    @Test
    fun testPasswordNeverSetChecksForSetPasswordToken() = testSuspend {
        val otherUserCN = "other-$userCN"
        val otherUserGUID = UUID.randomUUID()
        var passwordSet = setPasswordTokenService.passwordNeverSetForUserCN(otherUserCN)
        assertFalse(passwordSet)
        resetPasswordTokenService.createToken(otherUserCN, otherUserGUID)
        passwordSet = setPasswordTokenService.passwordNeverSetForUserCN(otherUserCN)
        assertFalse(passwordSet)
        setPasswordTokenService.createToken(otherUserCN, otherUserGUID)
        passwordSet = setPasswordTokenService.passwordNeverSetForUserCN(otherUserCN)
        assertTrue(passwordSet)
    }

    @Test
    fun testClearTokenForUserCn() = testSuspend {
        val clearTokenUserCn = "clear-token-$userCN"
        val clearTokenUserGUID = UUID.randomUUID()

        val token = setPasswordTokenService.createToken(clearTokenUserCn, clearTokenUserGUID)
        assertIs<PasswordTokenService.ValidToken>(
            setPasswordTokenService.validateToken(token, clearTokenUserCn, clearTokenUserGUID)
        )

        setPasswordTokenService.clearTokenForUserCn(clearTokenUserCn)

        assertIsNot<PasswordTokenService.ValidToken>(
            setPasswordTokenService.validateToken(token, clearTokenUserCn, clearTokenUserGUID)
        )
    }

    companion object {
        private const val userCN = "user!example.com"
        private val userGUID = UUID.fromString("00112233-4455-6677-8899-aabbccddeeff")
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
