import io.mockk.*
import org.junit.Assert.assertEquals
import org.junit.Test
import uk.gov.communities.delta.auth.config.LDAPConfig
import uk.gov.communities.delta.auth.repositories.LdapRepository
import javax.naming.directory.*

class LdapRepositoryTest {

    private val ldapConfig = mockk<LDAPConfig>(relaxed = true)
    private val ldapRepository = LdapRepository(ldapConfig, LdapRepository.ObjectGUIDMode.NEW_JAVA_UUID_STRING)


    @Test
    fun `createUserWithRoles constructs UserWithRoles correctly`() {
        val userAttrs: Attributes = mockk()
        every { userAttrs.get("cn")?.get() } returns "test-user"
        every { userAttrs.get("objectGUID")?.get() } returns ByteArray(16)
        every { userAttrs.get("mail")?.get() } returns "test@example.com"
        every { userAttrs.get("givenName")?.get() } returns "Test"
        every { userAttrs.get("sn")?.get() } returns "User"

        val allGroups = listOf(
            "CN=datamart-delta-data-providers-organisationId,OU=groups,DC=example,DC=com",
            "CN=datamart-delta-data-certifiers-organisationId,OU=groups,DC=example,DC=com",
            "CN=some-other-group,OU=groups,DC=example,DC=com"
        )

        val userWithRoles = ldapRepository.createUserWithRoles(userAttrs, allGroups, "organisationId")

        assertEquals("test-user", userWithRoles.cn)
        assertEquals("test@example.com", userWithRoles.mail)
        assertEquals("Test User", userWithRoles.fullName)
        assertEquals(listOf("Data provider", "Data certifier"), userWithRoles.roles)
    }
}
