package uk.gov.communities.delta.service

import io.ktor.server.application.*
import io.ktor.test.dispatcher.*
import io.mockk.*
import org.junit.Before
import org.junit.BeforeClass
import org.junit.Test
import uk.gov.communities.delta.auth.services.DeltaApiTokenService
import uk.gov.communities.delta.auth.services.UserAuditService
import uk.gov.communities.delta.auth.services.UserLookupService
import uk.gov.communities.delta.auth.utils.TimeSource
import uk.gov.communities.delta.dbintegration.testDbPool
import uk.gov.communities.delta.helper.testLdapUser
import uk.gov.communities.delta.helper.testServiceClient
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class DeltaApiTokenServiceTest {
    @Test
    fun canValidateApiClientIdAndSecret() = testSuspend {
        val result = service.validateApiClientIdAndSecret("valid_id", "valid_secret")
        assertTrue(result)
    }

    @Test
    fun rejectsInvalidClientIdAndSecret() = testSuspend {
        val result = service.validateApiClientIdAndSecret("ff", "gg")
        assertFalse(result)
    }

    @Test
    fun canCreateAndStoreAndValidateApiToken() = testSuspend {
        val userName = testUser.cn
        val userGuid = testUser.javaUUIDObjectGuid
        val userClientId = "valid_id"
        val fakeCall = mockk<ApplicationCall>()
        val token = service.createAndStoreApiToken(userName, userClientId, userGuid, fakeCall)
        val result = service.validateApiToken(token)
        assertEquals(Triple(userName, userClientId, userGuid), result)
        coVerify { userAuditService.apiTokenCreationAudit(userName, any()) }
    }

    @Test
    fun rejectsInvalidApiToken() = testSuspend {
        val token = "fake_token"
        val result = service.validateApiToken(token)
        assertEquals(null, result)
    }

    @Before
    fun resetMocks() {
        clearAllMocks()
        coEvery { userLookupService.lookupUserByCn(testUser.cn) } returns testUser
        coEvery { userAuditService.apiTokenCreationAudit(testUser.cn, any()) } just runs
    }

    companion object {
        lateinit var service: DeltaApiTokenService
        val client = testServiceClient()

        private val userLookupService = mockk<UserLookupService>()
        private val userAuditService = mockk<UserAuditService>()

        private val testUser = testLdapUser()

        @BeforeClass
        @JvmStatic
        fun setup() {
            service = DeltaApiTokenService(testDbPool, TimeSource.System, userLookupService, userAuditService)
            testDbPool.useConnectionBlocking("test_data_creation") {
                it.createStatement().execute("INSERT INTO api_clients (client_id, client_secret) VALUES ('valid_id', 'valid_secret')")
                it.commit()
            }
        }
    }
}
