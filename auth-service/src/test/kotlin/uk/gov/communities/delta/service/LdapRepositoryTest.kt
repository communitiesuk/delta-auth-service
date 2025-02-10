import io.mockk.*
import org.junit.Assert.assertEquals
import org.junit.Before
import org.junit.Test
import uk.gov.communities.delta.auth.config.LDAPConfig
import uk.gov.communities.delta.auth.repositories.LdapRepository
import javax.naming.NamingEnumeration
import javax.naming.directory.*
import javax.naming.ldap.InitialLdapContext


class LdapRepositoryTest {

    private val ldapConfig = LDAPConfig("testInvalidUrl", "", "", "CN=%s,OU=Groups,OU=test,DC=example,DC=local", "", "", "", "", "", "", "")
    private lateinit var ldapRepository: LdapRepository
    private lateinit var initialLdapContext: InitialLdapContext
    private lateinit var mockSearchResults: NamingEnumeration<SearchResult>

    @Before
    fun setUp() {
        initialLdapContext = mockk<InitialLdapContext>(relaxed = true)
        mockSearchResults = mockk(relaxed = true)
        coEvery { initialLdapContext.search(any<String>(), any<String>(), any<SearchControls>()) } returns mockSearchResults
        ldapRepository = LdapRepository(ldapConfig, LdapRepository.ObjectGUIDMode.NEW_JAVA_UUID_STRING) { initialLdapContext }
    }

    @Test
    fun `getUsersForOrgAccessGroupWithRoles constructs UserWithRoles correctly`() {
        val allGroups = listOf(
            "CN=datamart-delta-data-providers-my-org,OU=Groups,OU=test,DC=example,DC=local",
            "CN=datamart-delta-data-certifiers,OU=Groups,OU=test,DC=example,DC=local",
            "CN=some-other-group,OU=Groups,OU=test,DC=example,DC=com"
        )
        val searchResult = buildUser(allGroups)
        every { mockSearchResults.hasMore() } returns true andThen false
        every { mockSearchResults.next() } returns searchResult

        val result = ldapRepository.getUsersForOrgAccessGroupWithRoles("my-access-group", "my-org")

        assertEquals(1, result.size)
        val user = result[0]
        assertEquals("test-user", user.cn)
        assertEquals("test@example.com", user.mail)
        assertEquals("Test User", user.fullName)
        assertEquals(listOf("Data provider", "Data certifier"), user.roles)
    }

    @Test
    fun `getUsersForOrgAccessGroupWithRoles excludes internal users`() {
        val allGroups = listOf(
            "CN=datamart-delta-data-providers-my-org,OU=Groups,OU=test,DC=example,DC=local",
            "CN=datamart-delta-user-dclg,OU=Groups,OU=test,DC=example,DC=local"
        )
        val searchResult = buildUser(allGroups)
        every { mockSearchResults.hasMore() } returns true andThen false
        every { mockSearchResults.next() } returns searchResult

        val result = ldapRepository.getUsersForOrgAccessGroupWithRoles("my-access-group", "my-org")

        assertEquals(0, result.size)
    }

    @Test
    fun `getUsersForOrgAccessGroupWithRoles excludes disabled users`() {
        val searchResult = buildUser(enabled = false)
        every { mockSearchResults.hasMore() } returns true andThen false
        every { mockSearchResults.next() } returns searchResult

        val result = ldapRepository.getUsersForOrgAccessGroupWithRoles("my-access-group", "my-org")

        assertEquals(0, result.size)
    }

    private fun buildUser(
        allGroups: List<String> = listOf("CN=datamart-delta-data-providers-my-org,OU=Groups,OU=test,DC=example,DC=local"),
        enabled: Boolean = true
    ): SearchResult {
        val groupsIterator = allGroups.iterator()
        val userAttrs: Attributes = mockk(relaxed = true)
        val mockMemberOfEnumeration = mockk<NamingEnumeration<String>>()
        every { userAttrs.get(any())?.get() } returns null
        every { userAttrs.get("cn")?.get() } returns "test-user"
        every { userAttrs.get("objectGUID")?.get() } returns ByteArray(16)
        every { userAttrs.get("mail")?.get() } returns "test@example.com"
        every { userAttrs.get("givenName")?.get() } returns "Test"
        every { userAttrs.get("distinguishedName")?.get() } returns "foo"
        every { userAttrs.get("sn")?.get() } returns "User"
        every { userAttrs.get("userAccountControl")?.get() } returns if (enabled) "512" else "514"
        every { userAttrs.get("memberOf")?.all } returns mockMemberOfEnumeration
        every { mockMemberOfEnumeration.hasMoreElements() } coAnswers { groupsIterator.hasNext() }
        every { mockMemberOfEnumeration.nextElement() } coAnswers { groupsIterator.next() }

        val searchResult: SearchResult = mockk(relaxed = true)
        every { searchResult.attributes } returns userAttrs

        return searchResult
    }
}
