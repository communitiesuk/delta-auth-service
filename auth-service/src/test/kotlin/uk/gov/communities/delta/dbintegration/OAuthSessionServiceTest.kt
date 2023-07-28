package uk.gov.communities.delta.dbintegration

import org.junit.BeforeClass
import org.junit.Test
import uk.gov.communities.delta.auth.services.AuthCode
import uk.gov.communities.delta.auth.services.OAuthSessionService
import java.time.Instant
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull

class OAuthSessionServiceTest {
    @Test
    fun testLookupInvalidTokenFails() {
        val result = service.retrieveFomAuthToken("invalidToken")
        assertNull(result)
    }

    @Test
    fun testCreateAndRetrieveSession() {
        val authCode = AuthCode("code", "userCn", Instant.now(), "trace")
        val createResult = service.create(authCode)

        assertNotNull(createResult.id)
        assertEquals(authCode.userCn, createResult.userCn)
        assertEquals(authCode.traceId, createResult.traceId)

        val lookupResult = service.retrieveFomAuthToken(createResult.authToken)
        assertNotNull(lookupResult)
        // The created at timestamp loses some precision in the database so will not be exactly the same
        assertEquals(createResult.id, lookupResult.id)
        assertEquals(createResult.userCn, lookupResult.userCn)
        assertEquals(createResult.authToken, lookupResult.authToken)
        assertEquals(createResult.traceId, lookupResult.traceId)
    }

    companion object {
        lateinit var service: OAuthSessionService

        @BeforeClass
        @JvmStatic
        fun setup() {
            service = OAuthSessionService(testDbPool)
        }
    }
}
