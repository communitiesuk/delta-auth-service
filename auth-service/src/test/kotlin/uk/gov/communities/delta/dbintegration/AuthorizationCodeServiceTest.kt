package uk.gov.communities.delta.dbintegration

import org.junit.BeforeClass
import org.junit.Test
import uk.gov.communities.delta.auth.services.AuthorizationCodeService
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull

class AuthorizationCodeServiceTest {

    @Test
    fun testLookupInvalidCodeFails() {
        val result = service.lookupAndInvalidate("invalid_code")
        assertNull(result)
    }

    @Test
    fun testRetrieveValidCode() {
        val code = service.generateAndStore("some.user", "traceId")
        val result = service.lookupAndInvalidate(code.code)
        assertNotNull(result)
        assertEquals(result.userCn, "some.user")
        assertEquals(result.traceId, "traceId")
        assertNull(service.lookupAndInvalidate(code.code), "Each code should only be usable once")
    }

    companion object {
        lateinit var service: AuthorizationCodeService

        @BeforeClass
        @JvmStatic
        fun setup() {
            service = AuthorizationCodeService(testDbPool)
        }
    }
}
