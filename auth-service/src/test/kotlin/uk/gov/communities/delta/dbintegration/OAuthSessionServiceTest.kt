package uk.gov.communities.delta.dbintegration

import org.junit.BeforeClass
import org.junit.Test
import uk.gov.communities.delta.auth.services.AuthCode
import uk.gov.communities.delta.auth.services.OAuthSessionService
import uk.gov.communities.delta.auth.utils.TimeSource
import uk.gov.communities.delta.helper.testServiceClient
import java.time.Instant
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull

class OAuthSessionServiceTest {
    @Test
    fun testLookupInvalidTokenFails() {
        val result = service.retrieveFomAuthToken("invalidToken", client)
        assertNull(result)
    }

    @Test
    fun testLookupInvalidClientFails() {
        val authCode = AuthCode("code", "userCn", client, Instant.now(), "trace")
        val createResult = service.create(authCode, client)

        val result = service.retrieveFomAuthToken(createResult.authToken, testServiceClient("wrong-client"))
        assertNull(result)
    }

    @Test
    fun testCreateAndRetrieveSession() {
        val authCode = AuthCode("code", "userCn", client, Instant.now(), "trace")
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
        val client = testServiceClient()

        @BeforeClass
        @JvmStatic
        fun setup() {
            service = OAuthSessionService(testDbPool, TimeSource.System)
        }
    }
}
