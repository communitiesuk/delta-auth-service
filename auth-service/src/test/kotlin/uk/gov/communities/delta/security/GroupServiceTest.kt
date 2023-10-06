package uk.gov.communities.delta.security

import io.ktor.test.dispatcher.*
import io.mockk.coEvery
import io.mockk.mockk
import io.mockk.slot
import io.mockk.verify
import org.junit.Before
import org.junit.Test
import uk.gov.communities.delta.auth.config.LDAPConfig
import uk.gov.communities.delta.auth.services.GroupService
import uk.gov.communities.delta.auth.services.LdapService
import uk.gov.communities.delta.auth.services.Registration
import uk.gov.communities.delta.auth.services.UserService
import javax.naming.directory.*
import javax.naming.ldap.InitialLdapContext
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class GroupServiceTest {
    private val ldapService = mockk<LdapService>()
    private val groupCN = "datamart-delta-group"
    private val groupDnFormat = "CN=%s"
    private val groupDN = String.format(groupDnFormat, groupCN)
    private val ldapConfig = LDAPConfig("testInvalidUrl", "", "", groupDnFormat, "", "", "", "")
    private val groupService = GroupService(ldapService, ldapConfig)
    private val container = slot<Attributes>()
    private val modificationItems = slot<Array<ModificationItem>>()
    private val context = mockk<InitialLdapContext>()
    private val contextBlock = slot<(InitialLdapContext) -> Any>()
    private val adUser = UserService.ADUser(Registration("Test", "User", "user@example.com"), false, ldapConfig)
    private val attributes = BasicAttributes()

    @Before
    fun setupMocks() {
        attributes.put(BasicAttribute("cn", groupCN))
        coEvery { ldapService.useServiceUserBind(capture(contextBlock)) } coAnswers { contextBlock.captured(context) }
        coEvery { context.createSubcontext(groupDN, capture(container)) } coAnswers { nothing }
        coEvery { context.modifyAttributes(groupDN, capture(modificationItems)) } coAnswers { nothing }
    }

    @Test
    fun testGroupExists() = testSuspend {
        coEvery { context.getAttributes(groupDN, arrayOf("cn")) } coAnswers { attributes }
        val groupExists = groupService.groupExists(groupDN)
        verify(exactly = 1) { context.getAttributes(groupDN, arrayOf("cn")) }
        assertTrue(groupExists)
    }

    @Test
    fun testGroupDoesNotExist() = testSuspend {
        coEvery { context.getAttributes("falseDN", arrayOf("cn")) } coAnswers { BasicAttributes() }
        val groupExists = groupService.groupExists("falseDN")
        verify(exactly = 1) { context.getAttributes("falseDN", arrayOf("cn")) }
        assertFalse(groupExists)
    }

    @Test
    fun testGroupCreation() = testSuspend {
        coEvery {
            context.getAttributes(
                groupDN,
                arrayOf("cn")
            )
        } coAnswers { BasicAttributes() } coAndThen { attributes }
        groupService.createGroup(groupCN)
        verify(exactly = 1) { context.createSubcontext(groupDN, any()) }
        assertEquals(groupCN, container.captured.get("cn").get())
    }

    @Test
    fun testAddingUserToExistingGroup() = testSuspend {
        coEvery { context.getAttributes(groupDN, arrayOf("cn")) } coAnswers { attributes }
        groupService.addUserToGroup(adUser, groupCN)
        verify(exactly = 0) { context.createSubcontext(groupDN, any()) }
        verify(exactly = 1) { context.modifyAttributes(groupDN, any()) }
        assertEquals(DirContext.ADD_ATTRIBUTE, modificationItems.captured[0].modificationOp)
        assertEquals(adUser.dn, modificationItems.captured[0].attribute.get())
    }

    @Test
    fun testGroupCreationOnAddingUserToNotExistingGroup() = testSuspend {
        coEvery {
            context.getAttributes(
                groupDN,
                arrayOf("cn")
            )
        } coAnswers { BasicAttributes() } coAndThen { attributes }
        groupService.addUserToGroup(adUser, groupCN)
        verify(exactly = 1) { context.createSubcontext(groupDN, any()) }
        assertEquals(groupCN, container.captured.get("cn").get())
        verify(exactly = 1) { context.modifyAttributes(groupDN, any()) }
        assertEquals(DirContext.ADD_ATTRIBUTE, modificationItems.captured[0].modificationOp)
        assertEquals(adUser.dn, modificationItems.captured[0].attribute.get())
    }
}