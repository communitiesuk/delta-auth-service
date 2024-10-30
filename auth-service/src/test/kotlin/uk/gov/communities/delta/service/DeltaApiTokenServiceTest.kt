package uk.gov.communities.delta.service

import io.ktor.server.application.*
import io.ktor.test.dispatcher.*
import io.mockk.*
import org.junit.AfterClass
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
import java.util.*
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
        val userGuid = testUser.getGUID()
        val userClientId = "valid_id"
        val fakeCall = mockk<ApplicationCall>()
        val token = service.createAndStoreApiToken(userName, userClientId, userGuid, fakeCall)
        val result = service.validateApiToken(token)
        assertEquals(Triple(userName, userClientId, userGuid), result)
        coVerify { userAuditService.apiTokenCreationAudit(userGuid, any()) }
    }

    @Test
    fun rejectsInvalidApiToken() = testSuspend {
        val token = Base64.getEncoder().encodeToString("fake_token".toByteArray())
        val result = service.validateApiToken(token)
        assertEquals(null, result)
    }

    @Before
    fun resetMocks() {
        clearAllMocks()
        coEvery { userAuditService.apiTokenCreationAudit(testUser.getGUID(), any()) } just runs
    }

    companion object {
        lateinit var service: DeltaApiTokenService
        val client = testServiceClient()
        private val userAuditService = mockk<UserAuditService>()

        private val testUser = testLdapUser()

        @BeforeClass
        @JvmStatic
        fun setup() {
            service = DeltaApiTokenService(testDbPool, TimeSource.System, userAuditService)
            testDbPool.useConnectionBlocking("test_data_creation") {
                it.createStatement().execute("INSERT INTO api_clients (client_id, client_secret) VALUES ('valid_id', 'valid_secret')")
                it.commit()
            }
        }

        @AfterClass
        @JvmStatic
        fun teardown() {
            testDbPool.useConnectionBlocking("test_data_removal") {
                it.createStatement().execute("DELETE FROM api_tokens")
                it.createStatement().execute("DELETE FROM api_clients")
                it.commit()
            }
        }
    }
}
