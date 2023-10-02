package uk.gov.communities.delta.dbintegration

import io.ktor.test.dispatcher.*
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.junit.BeforeClass
import org.junit.Test
import uk.gov.communities.delta.auth.services.SetPasswordTokenService
import uk.gov.communities.delta.auth.utils.TimeSource
import uk.gov.communities.delta.helper.testServiceClient
import java.sql.Timestamp
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class SetPasswordTokenServiceTest {
    @Test
    fun testLookupInvalidTokenFails() = testSuspend {
        val result = service.useToken("invalidToken", userCN)
        assertTrue(result is SetPasswordTokenService.NoSuchToken)
    }

    @Test
    fun testLookupWrongUserFails() = testSuspend {
        val token = service.createToken(userCN)
        val result = service.useToken(token, "not$userCN")
        assertTrue(result is SetPasswordTokenService.NoSuchToken)
    }

    @Test
    fun testLookupCorrectUserWithoutDelete() = testSuspend {
        val token = service.createToken(userCN)
        val result = service.useToken(token, userCN)
        assertTrue(result is SetPasswordTokenService.ValidToken)
    }

    @Test
    fun testLookupWithDelete() = testSuspend {
        val token = service.createToken(userCN)
        var result = service.useToken(token, userCN, true)
        assertTrue(result is SetPasswordTokenService.ValidToken)
        result = service.useToken(token, userCN)
        assertTrue(result is SetPasswordTokenService.NoSuchToken)
    }

    @Test
    fun testLookupWithoutDelete() = testSuspend {
        val token = service.createToken(userCN)
        var result = service.useToken(token, userCN, false)
        assertTrue(result is SetPasswordTokenService.ValidToken)
        result = service.useToken(token, userCN)
        assertTrue(result is SetPasswordTokenService.ValidToken)
    }

    @Test
    fun testOnlyOneTokenPerUser() = testSuspend {
        val originalToken = service.createToken(userCN)
        val replacementToken = service.createToken(userCN)
        var result = service.useToken(originalToken, userCN)
        assertTrue(result is SetPasswordTokenService.NoSuchToken)
        result = service.useToken(replacementToken, userCN, true)
        assertTrue(result is SetPasswordTokenService.ValidToken)
    }

    @Test
    fun testLookupExpiredToken() = testSuspend {
        val token = service.createToken(userCN)
        withContext(Dispatchers.IO) {
            testDbPool.useConnection {
                val stmt = it.prepareStatement(
                    "UPDATE set_password_tokens SET created_at = ? WHERE user_cn = ? "
                )
                stmt.setTimestamp(
                    1,
                    Timestamp.from(
                        TimeSource.System.now().minusSeconds(SetPasswordTokenService.TOKEN_VALID_DURATION_SECONDS)
                    )
                )
                stmt.setString(2, userCN)
                stmt.executeUpdate()
                it.commit()
            }
        }
        val result = service.useToken(token, userCN)
        assertTrue(result is SetPasswordTokenService.ExpiredToken)
    }

    @Test
    fun testTokenCreation() = testSuspend {
        val token = service.createToken(userCN)
        assertEquals(SetPasswordTokenService.TOKEN_LENGTH_BYTES * 8/6, token.length)
    }

    companion object {
        private val userCN = "user!example.com"
        lateinit var service: SetPasswordTokenService
        val client = testServiceClient()

        @BeforeClass
        @JvmStatic
        fun setup() {
            service = SetPasswordTokenService(testDbPool, TimeSource.System)
        }
    }
}