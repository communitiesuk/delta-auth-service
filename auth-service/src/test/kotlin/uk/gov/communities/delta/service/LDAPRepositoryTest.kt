import io.mockk.*
import org.junit.Assert.assertEquals
import org.junit.Test
import uk.gov.communities.delta.auth.config.LDAPConfig
import uk.gov.communities.delta.auth.repositories.LdapRepository
import javax.naming.NamingEnumeration
import javax.naming.directory.*
import javax.naming.ldap.InitialLdapContext

class LdapRepositoryTest {

    private val ldapConfig = mockk<LDAPConfig>(relaxed = true)
    private val ctx = mockk<InitialLdapContext>()
    private val ldapRepository = LdapRepository(ldapConfig, LdapRepository.ObjectGUIDMode.NEW_JAVA_UUID_STRING)

    @Test
    fun `getUsersForOrgAccessGroupWithRoles - retrieves users with roles`() {
        every { ldapConfig.authServiceUserDn } returns "userDn"
        every { ldapConfig.authServiceUserPassword } returns "password"
        every { ldapConfig.userContainerDn } returns "CN=Users,DC=example,DC=com"
        every { ldapConfig.accessGroupContainerDn } returns "CN=AccessGroups,DC=example,DC=com"
        every { ldapConfig.deltaLdapUrl } returns "ldap://example.com"
        every { ldapConfig.groupDnFormat } returns "CN=%s,OU=groups,DC=example,DC=com"

        every { ldapRepository.bind(any(), any(), any()) } returns ctx

        val searchResultMock: SearchResult = mockk()
        val attributesMock: Attributes = mockk()

        val namingEnumeration: NamingEnumeration<SearchResult> = mockk()

        every { ctx.search(any<String>(), any<String>(), any<SearchControls>()) } returns namingEnumeration
        every { namingEnumeration.hasMore() } returnsMany listOf(true, false)
        every { namingEnumeration.next() } returns searchResultMock

        every { searchResultMock.attributes } returns attributesMock
        every { attributesMock.get("cn")?.get() } returns "test-user"
        every { attributesMock.get("objectGUID")?.get() } returns ByteArray(16)
        every { attributesMock.get("mail")?.get() } returns "test@example.com"
        every { attributesMock.get("givenName")?.get() } returns "Test"
        every { attributesMock.get("sn")?.get() } returns "User"
        every { attributesMock.get("userAccountControl")?.get() } returns "512" // Account enabled

        val memberOfAttributeMock: Attribute = mockk()
        val memberOfEnumeration: NamingEnumeration<String> = mockk()

        every { memberOfEnumeration.hasMore() } returnsMany listOf(true, false)
        every { memberOfEnumeration.next() } returns "CN=datamart-delta-data-providers-123,OU=groups,DC=example,DC=com"

        every { memberOfAttributeMock.all } returns memberOfEnumeration
        every { attributesMock.get("memberOf") } returns memberOfAttributeMock

        val usersWithRoles = ldapRepository.getUsersForOrgAccessGroupWithRoles("accessGroupName", "organisationId")

        assertEquals(1, usersWithRoles.size)
        assertEquals("test-user", usersWithRoles[0].cn)
        assertEquals("test@example.com", usersWithRoles[0].mail)
        assertEquals("Test User", usersWithRoles[0].fullName)
        assertEquals(listOf("Data provider"), usersWithRoles[0].roles)
    }

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
