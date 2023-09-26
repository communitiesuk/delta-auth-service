package uk.gov.communities.delta.security

import io.ktor.test.dispatcher.*
import io.mockk.every
import io.mockk.mockk
import io.mockk.verify
import org.junit.Before
import uk.gov.communities.delta.auth.security.ADLdapLoginService
import uk.gov.communities.delta.auth.security.IADLdapLoginService
import uk.gov.communities.delta.auth.services.LdapService
import uk.gov.communities.delta.helper.testLdapUser
import javax.naming.ldap.InitialLdapContext
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class ADLdapLoginServiceTest {
    private lateinit var loginService: ADLdapLoginService
    private lateinit var ldapService: LdapService

    @Before
    fun setup() {
        ldapService = mockk<LdapService>()
        loginService = ADLdapLoginService(
            ADLdapLoginService.Configuration("CN=%s,OU=Users,DC=test"),
            ldapService
        )
        val mockContext = mockk<InitialLdapContext>(relaxed = true)
        every { ldapService.bind("CN=username,OU=Users,DC=test", "password") }.returns(mockContext)
        every { ldapService.mapUserFromContext(mockContext, "CN=username,OU=Users,DC=test") }.returns(testLdapUser())
    }

    @Test
    fun successfulLogin() = testSuspend {
        val result = loginService.ldapLogin("username", "password")

        assertTrue(result is IADLdapLoginService.LdapLoginSuccess)
        assertEquals(result.user, testLdapUser())
    }

    @Test
    fun checksUsername() = testSuspend {
        val result = loginService.ldapLogin("invalid=username", "password")

        assertTrue(result is IADLdapLoginService.InvalidUsername)
        verify(exactly = 0) { ldapService.bind(any(), any()) }
    }
}
