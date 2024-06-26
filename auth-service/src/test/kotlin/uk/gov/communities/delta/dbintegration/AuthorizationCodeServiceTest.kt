package uk.gov.communities.delta.dbintegration

import io.ktor.test.dispatcher.*
import org.junit.BeforeClass
import org.junit.Test
import uk.gov.communities.delta.auth.services.AuthorizationCodeService
import uk.gov.communities.delta.auth.utils.TimeSource
import uk.gov.communities.delta.helper.testServiceClient
import java.util.*
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull

class AuthorizationCodeServiceTest {

    @Test
    fun testLookupInvalidCodeFails() = testSuspend {
        val result = service.lookupAndInvalidate("invalid_code", client)
        assertNull(result)
    }

    @Test
    fun testLookupCodeWrongClientFails() = testSuspend {
        val code = service.generateAndStore(userGUID, client, "traceId", false)
        val result = service.lookupAndInvalidate(code.code, testServiceClient("wrong-client"))
        assertNull(result)
    }

    @Test
    fun testRetrieveValidCode() = testSuspend {
        val code = service.generateAndStore(userGUID, client, "traceId", true)
        val result = service.lookupAndInvalidate(code.code, client)
        assertNotNull(result)
        assertEquals(result.userGUID, userGUID)
        assertEquals(result.traceId, "traceId")
        assertEquals(result.isSso, true)
        assertNull(service.lookupAndInvalidate(code.code, client), "Each code should only be usable once")
    }

    companion object {
        lateinit var service: AuthorizationCodeService
        val client = testServiceClient()
        val userGUID: UUID = UUID.randomUUID()

        @BeforeClass
        @JvmStatic
        fun setup() {
            service = AuthorizationCodeService(testDbPool, TimeSource.System)
        }
    }
}
