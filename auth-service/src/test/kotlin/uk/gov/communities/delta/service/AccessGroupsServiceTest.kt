import io.mockk.MockKAnnotations
import io.mockk.mockk
import org.junit.Before
import org.junit.Test
import uk.gov.communities.delta.auth.config.LDAPConfig
import uk.gov.communities.delta.auth.services.AccessGroupsService
import uk.gov.communities.delta.auth.services.LdapServiceUserBind
import kotlin.test.assertFailsWith

class AccessGroupsServiceTest {

    private lateinit var ldapServiceUserBind: LdapServiceUserBind
    private lateinit var config: LDAPConfig
    private lateinit var accessGroupsService: AccessGroupsService

    @Before
    fun setUp() {
        MockKAnnotations.init(this)
        ldapServiceUserBind = mockk()
        config = mockk()
        accessGroupsService = AccessGroupsService(ldapServiceUserBind, config)
    }

    // Test for valid access group name
    @Test
    fun `checkAccessGroupNameIsValid - valid names do not throw exceptions`() {
        val validNames = listOf("workflow-1-test-dclg", "somuchtesting-dclg", "central-list-dclg")

        for (name in validNames) {
            accessGroupsService.checkAccessGroupNameIsValid(name)
        }
    }

    // Test for invalid access group name
    @Test
    fun `checkAccessGroupNameIsValid - invalid names throw IllegalArgumentException`() {
        val invalidNames = listOf("123central-list-dclg", "-central-list-dclg", "central-list-dclg*", "central-list-dclg$", "CENTRAL-LIST-DCLG")

        for (name in invalidNames) {
            assertFailsWith<IllegalArgumentException> {
                accessGroupsService.checkAccessGroupNameIsValid(name)
            }
        }
    }

    // Test for valid access group prefix
    @Test
    fun `checkAccessGroupPrefixIsValid - valid prefixes do not throw exceptions`() {
        val validPrefix = "data-delta-central-list-dclg"

        accessGroupsService.checkAccessGroupPrefixIsValid(validPrefix)
    }

    // Test for invalid access group prefix (with datamart-delta prefix)
    @Test
    fun `checkAccessGroupPrefixIsValid - invalid prefix throws IllegalArgumentException`() {
        val invalidPrefix = "datamart-delta-prefix-central-list-dclg"

        assertFailsWith<IllegalArgumentException> {
            accessGroupsService.checkAccessGroupPrefixIsValid(invalidPrefix)
        }
    }
}
