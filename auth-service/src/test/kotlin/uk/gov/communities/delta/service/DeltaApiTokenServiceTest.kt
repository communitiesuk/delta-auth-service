package uk.gov.communities.delta.service

import io.ktor.test.dispatcher.*
import org.junit.BeforeClass
import org.junit.Test
import uk.gov.communities.delta.auth.services.DeltaApiTokenService
import uk.gov.communities.delta.auth.utils.TimeSource
import uk.gov.communities.delta.dbintegration.testDbPool
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
        val userName = "user_name"
        val token = service.createAndStoreApiToken(userName, "valid_id")
        val result = service.validateApiToken(token)
        assertEquals(userName, result)
    }

    companion object {
        lateinit var service: DeltaApiTokenService
        val client = testServiceClient()

        @BeforeClass
        @JvmStatic
        fun setup() {
            service = DeltaApiTokenService(testDbPool, TimeSource.System)
            testDbPool.useConnectionBlocking("test_data_creation") {
                it.createStatement().execute("INSERT INTO api_clients (client_id, client_secret) VALUES ('valid_id', 'valid_secret')")
                it.commit()
            }
        }
    }
}
