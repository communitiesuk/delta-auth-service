package uk.gov.communities.delta.dbintegration

import io.ktor.test.dispatcher.*
import io.mockk.mockk
import org.junit.BeforeClass
import org.junit.Test
import uk.gov.communities.delta.auth.repositories.UserGUIDMapRepo
import uk.gov.communities.delta.auth.services.AuthCode
import uk.gov.communities.delta.auth.services.OAuthSessionService
import uk.gov.communities.delta.auth.services.UserGUIDMapService
import uk.gov.communities.delta.auth.utils.TimeSource
import uk.gov.communities.delta.helper.testLdapUser
import uk.gov.communities.delta.helper.testServiceClient
import java.time.Instant
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull

class OAuthSessionServiceTest {
    @Test
    fun testLookupInvalidTokenFails() = testSuspend {
        val result = service.retrieveFromAuthToken("invalidToken", client)
        assertNull(result)
    }

    @Test
    fun testLookupInvalidClientFails() = testSuspend {
        val authCode = AuthCode("code", user.getGUID(), client, Instant.now(), "trace", false)
        userGUIDMapService.addNewUser(user)
        val createResult = service.create(authCode, client)

        val result = service.retrieveFromAuthToken(createResult.authToken, testServiceClient("wrong-client"))
        assertNull(result)
    }

    @Test
    fun testCreateAndRetrieveSession() = testSuspend {
        val authCode = AuthCode("code", user.getGUID(), client, Instant.now(), "trace", false)
        userGUIDMapService.addNewUser(user)
        val createResult = service.create(authCode, client)

        assertNotNull(createResult.id)
        assertEquals(authCode.userGUID, createResult.userGUID)
        assertEquals(user.cn, createResult.userCn)
        assertEquals(authCode.traceId, createResult.traceId)

        val lookupResult = service.retrieveFromAuthToken(createResult.authToken, client)
        assertNotNull(lookupResult)
        // The created at timestamp loses some precision in the database so will not be exactly the same
        assertEquals(createResult.id, lookupResult.id)
        assertEquals(createResult.userCn, lookupResult.userCn)
        assertEquals(createResult.userGUID, lookupResult.userGUID)
        assertEquals(createResult.authToken, lookupResult.authToken)
        assertEquals(createResult.traceId, lookupResult.traceId)
    }

    companion object {
        lateinit var service: OAuthSessionService
        lateinit var userGUIDMapService: UserGUIDMapService
        private lateinit var userGUIDMapRepo: UserGUIDMapRepo
        private val user = testLdapUser(cn = "OAuthSessionServiceTestUserCN")
        val client = testServiceClient()

        @BeforeClass
        @JvmStatic
        fun setup() {
            userGUIDMapRepo = UserGUIDMapRepo()
            service = OAuthSessionService(testDbPool, TimeSource.System, userGUIDMapRepo)
            userGUIDMapService = UserGUIDMapService(userGUIDMapRepo, mockk(), testDbPool)
        }
    }
}
