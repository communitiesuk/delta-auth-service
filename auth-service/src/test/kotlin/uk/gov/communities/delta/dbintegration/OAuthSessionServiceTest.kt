package uk.gov.communities.delta.dbintegration

import io.ktor.test.dispatcher.*
import org.junit.BeforeClass
import org.junit.Test
import uk.gov.communities.delta.auth.services.AuthCode
import uk.gov.communities.delta.auth.services.OAuthSessionService
import uk.gov.communities.delta.auth.utils.TimeSource
import uk.gov.communities.delta.helper.testServiceClient
import java.time.Instant
import java.util.*
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull

class OAuthSessionServiceTest {
    @Test
    fun testLookupInvalidTokenFails() = testSuspend {
        val result = service.retrieveFomAuthToken("invalidToken", client)
        assertNull(result)
    }

    @Test
    fun testLookupInvalidClientFails() = testSuspend {
        val authCode = AuthCode("code", "userCn", userGUID, client, Instant.now(), "trace", false)
        val createResult = service.create(authCode, client)

        val result = service.retrieveFomAuthToken(createResult.authToken, testServiceClient("wrong-client"))
        assertNull(result)
    }

    @Test
    fun testCreateAndRetrieveSession() = testSuspend {
        val authCode = AuthCode("code", "userCn", userGUID, client, Instant.now(), "trace", false)
        val createResult = service.create(authCode, client)

        assertNotNull(createResult.id)
        assertEquals(authCode.userCn, createResult.userCn)
        assertEquals(authCode.traceId, createResult.traceId)

        val lookupResult = service.retrieveFomAuthToken(createResult.authToken, client)
        assertNotNull(lookupResult)
        // The created at timestamp loses some precision in the database so will not be exactly the same
        assertEquals(createResult.id, lookupResult.id)
        assertEquals(createResult.userCn, lookupResult.userCn)
        assertEquals(createResult.authToken, lookupResult.authToken)
        assertEquals(createResult.traceId, lookupResult.traceId)
    }

    companion object {
        lateinit var service: OAuthSessionService
        private val userGUID = UUID.fromString("00112233-4455-6677-8899-aabbccddeeff")
        val client = testServiceClient()

        @BeforeClass
        @JvmStatic
        fun setup() {
            service = OAuthSessionService(testDbPool, TimeSource.System)
        }
    }
}
