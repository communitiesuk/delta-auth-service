package uk.gov.communities.delta.dbintegration

import org.junit.BeforeClass
import org.junit.Test
import uk.gov.communities.delta.auth.services.AuthorizationCodeService
import uk.gov.communities.delta.auth.utils.TimeSource
import uk.gov.communities.delta.helper.testServiceClient
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull

class AuthorizationCodeServiceTest {

    @Test
    fun testLookupInvalidCodeFails() {
        val result = service.lookupAndInvalidate("invalid_code", client)
        assertNull(result)
    }

    @Test
    fun testLookupCodeWrongClientFails() {
        val code = service.generateAndStore("some.user", client, "traceId")
        val result = service.lookupAndInvalidate(code.code, testServiceClient("wrong-client"))
        assertNull(result)
    }

    @Test
    fun testRetrieveValidCode() {
        val code = service.generateAndStore("some.user", client, "traceId")
        val result = service.lookupAndInvalidate(code.code, client)
        assertNotNull(result)
        assertEquals(result.userCn, "some.user")
        assertEquals(result.traceId, "traceId")
        assertNull(service.lookupAndInvalidate(code.code, client), "Each code should only be usable once")
    }

    companion object {
        lateinit var service: AuthorizationCodeService
        val client = testServiceClient()

        @BeforeClass
        @JvmStatic
        fun setup() {
            service = AuthorizationCodeService(testDbPool, TimeSource.System)
        }
    }
}
