package uk.gov.communities.delta.security

import io.ktor.test.dispatcher.*
import io.mockk.every
import io.mockk.mockk
import io.mockk.verify
import org.junit.Before
import uk.gov.communities.delta.auth.repositories.LdapRepository
import uk.gov.communities.delta.auth.repositories.LdapUser
import uk.gov.communities.delta.auth.security.ADLdapLoginService
import uk.gov.communities.delta.auth.security.IADLdapLoginService
import uk.gov.communities.delta.helper.testLdapUser
import javax.naming.ldap.InitialLdapContext
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class ADLdapLoginServiceTest {
    private lateinit var loginService: ADLdapLoginService
    private lateinit var ldapRepository: LdapRepository
    private lateinit var user: LdapUser

    @Before
    fun setup() {
        ldapRepository = mockk<LdapRepository>()
        loginService = ADLdapLoginService(
            ADLdapLoginService.Configuration("CN=%s,OU=Users,DC=test"),
            ldapRepository,
        )
        val mockContext = mockk<InitialLdapContext>(relaxed = true)
        user = testLdapUser()
        every { ldapRepository.bind("CN=username,OU=Users,DC=test", "password") }.returns(mockContext)
        every { ldapRepository.mapUserFromContext(mockContext, "CN=username,OU=Users,DC=test") }.returns(user)
    }

    @Test
    fun successfulLogin() = testSuspend {
        val result = loginService.ldapLogin("username", "password")

        assertTrue(result is IADLdapLoginService.LdapLoginSuccess)
        assertEquals(result.user, user)
    }

    @Test
    fun checksUsername() = testSuspend {
        val result = loginService.ldapLogin("invalid=username", "password")

        assertTrue(result is IADLdapLoginService.InvalidUsername)
        verify(exactly = 0) { ldapRepository.bind(any(), any()) }
    }
}
