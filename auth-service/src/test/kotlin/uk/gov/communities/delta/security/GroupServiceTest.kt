package uk.gov.communities.delta.security

import io.ktor.server.application.*
import io.ktor.test.dispatcher.*
import io.mockk.*
import kotlinx.coroutines.runBlocking
import org.junit.Assert
import org.junit.Before
import org.junit.Test
import uk.gov.communities.delta.auth.config.DeltaLoginEnabledClient
import uk.gov.communities.delta.auth.config.LDAPConfig
import uk.gov.communities.delta.auth.services.GroupService
import uk.gov.communities.delta.auth.services.LdapServiceUserBind
import uk.gov.communities.delta.auth.services.OAuthSession
import uk.gov.communities.delta.auth.services.UserAuditService
import uk.gov.communities.delta.helper.testLdapUser
import java.time.Instant
import java.util.*
import javax.naming.NameNotFoundException
import javax.naming.directory.*
import javax.naming.ldap.InitialLdapContext
import kotlin.test.assertContains
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class GroupServiceTest {
    private val ldapServiceUserBind = mockk<LdapServiceUserBind>()
    private val userAuditService = mockk<UserAuditService>()
    private val groupCN = "datamart-delta-group"
    private val groupDnFormat = "CN=%s"
    private val groupDN = String.format(groupDnFormat, groupCN)
    private val ldapConfig = LDAPConfig("testInvalidUrl", "", "", groupDnFormat, "", "", "", "", "")
    private val groupService = GroupService(ldapServiceUserBind, ldapConfig, userAuditService)
    private val container = slot<Attributes>()
    private val modificationItems = slot<Array<ModificationItem>>()
    private val context = mockk<InitialLdapContext>()
    private val contextBlock = slot<(InitialLdapContext) -> Any>()
    private val ldapUser = testLdapUser(email = "user@example.com", cn = "user!example.com")
    private val adminGUID = UUID.fromString("ffeeddcc-bbaa-9988-7766-554433221100")
    private val attributes = BasicAttributes()
    private val call = mockk<ApplicationCall>()
    private val auditData = slot<String>()

    @Before
    fun setupMocks() {
        auditData.clear()
        attributes.put(BasicAttribute("cn", groupCN))
        coEvery { ldapServiceUserBind.useServiceUserBind(capture(contextBlock)) } coAnswers { contextBlock.captured(context) }
        coEvery { context.createSubcontext(groupDN, capture(container)) } coAnswers { nothing }
        coEvery { context.modifyAttributes(groupDN, capture(modificationItems)) } coAnswers { nothing }
        coEvery { userAuditService.userUpdateAudit(any(), any(), capture(auditData)) } just runs
        coEvery { userAuditService.userUpdateByAdminAudit(any(), any(), any(), capture(auditData)) } just runs
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
        coEvery { context.getAttributes("falseDN", arrayOf("cn")) } throws NameNotFoundException("Does not exist")
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
        groupService.addUserToGroup(ldapUser, groupCN, call, null)
        verify(exactly = 0) { context.createSubcontext(groupDN, any()) }
        verify(exactly = 1) { context.modifyAttributes(groupDN, any()) }
        assertEquals(DirContext.ADD_ATTRIBUTE, modificationItems.captured[0].modificationOp)
        assertEquals(ldapUser.dn, modificationItems.captured[0].attribute.get())
        coVerify(exactly = 1) { userAuditService.userUpdateAudit(ldapUser.getGUID(), call, any()) }
        assertContains(auditData.captured, "\"addedGroupCN\":\"$groupCN\"")
    }

    @Test
    fun testAdminAddingUserToExistingGroup() = testSuspend {
        val adminSession = OAuthSession(
            1,
            "admin",
            adminGUID,
            mockk<DeltaLoginEnabledClient>(),
            "adminAccessToken",
            Instant.now(),
            "trace",
            false
        )
        coEvery { context.getAttributes(groupDN, arrayOf("cn")) } coAnswers { attributes }
        groupService.addUserToGroup(ldapUser, groupCN, call, adminSession)
        verify(exactly = 0) { context.createSubcontext(groupDN, any()) }
        verify(exactly = 1) { context.modifyAttributes(groupDN, any()) }
        assertEquals(DirContext.ADD_ATTRIBUTE, modificationItems.captured[0].modificationOp)
        assertEquals(ldapUser.dn, modificationItems.captured[0].attribute.get())
        coVerify(exactly = 1) { userAuditService.userUpdateByAdminAudit(ldapUser.getGUID(), adminGUID, call, any()) }
        assertContains(auditData.captured, "\"addedGroupCN\":\"$groupCN\"")
    }

    @Test
    fun testGroupCreationOnAddingUserToNotExistingGroup() = testSuspend {
        coEvery {
            context.getAttributes(
                groupDN,
                arrayOf("cn")
            )
        } coAnswers { BasicAttributes() } coAndThen { attributes }
        groupService.addUserToGroup(ldapUser, groupCN, call, null)
        verify(exactly = 1) { context.createSubcontext(groupDN, any()) }
        assertEquals(groupCN, container.captured.get("cn").get())
        verify(exactly = 1) { context.modifyAttributes(groupDN, any()) }
        assertEquals(DirContext.ADD_ATTRIBUTE, modificationItems.captured[0].modificationOp)
        assertEquals(ldapUser.dn, modificationItems.captured[0].attribute.get())
        assertContains(auditData.captured, "\"addedGroupCN\":\"$groupCN\"")
    }

    @Test
    fun testRemovingUserFromGroup() = testSuspend {
        coEvery { context.getAttributes(groupDN, arrayOf("cn")) } coAnswers { attributes }
        groupService.removeUserFromGroup(ldapUser, groupCN, call, null)
        verify(exactly = 0) { context.createSubcontext(groupDN, any()) }
        verify(exactly = 1) { context.modifyAttributes(groupDN, any()) }
        assertEquals(DirContext.REMOVE_ATTRIBUTE, modificationItems.captured[0].modificationOp)
        assertEquals(ldapUser.dn, modificationItems.captured[0].attribute.get())
        coVerify(exactly = 1) { userAuditService.userUpdateAudit(ldapUser.getGUID(), call, any()) }
        assertContains(auditData.captured, "\"removedGroupCN\":\"$groupCN\"")
    }

    @Test
    fun testAdminRemovingUserFromGroup() = testSuspend {
        val adminSession = OAuthSession(
            1,
            "admin",
            adminGUID,
            mockk<DeltaLoginEnabledClient>(),
            "adminAccessToken",
            Instant.now(),
            "trace",
            false
        )
        coEvery { context.getAttributes(groupDN, arrayOf("cn")) } coAnswers { attributes }
        groupService.removeUserFromGroup(ldapUser, groupCN, call, adminSession)
        verify(exactly = 0) { context.createSubcontext(groupDN, any()) }
        verify(exactly = 1) { context.modifyAttributes(groupDN, any()) }
        assertEquals(DirContext.REMOVE_ATTRIBUTE, modificationItems.captured[0].modificationOp)
        assertEquals(ldapUser.dn, modificationItems.captured[0].attribute.get())
        coVerify(exactly = 1) { userAuditService.userUpdateByAdminAudit(ldapUser.getGUID(), adminGUID, call, any()) }
        assertContains(auditData.captured, "\"removedGroupCN\":\"$groupCN\"")
    }

    @Test
    fun testErrorThrownOnRemovingUserFromNotExistingGroup() = testSuspend {
        Assert.assertThrows(Exception::class.java) {
            runBlocking {
                groupService.addUserToGroup(ldapUser, groupCN, call, null)
            }
        }.apply {
            verify(exactly = 0) { context.createSubcontext(any<String>(), any()) }
            verify(exactly = 0) { context.modifyAttributes(any<String>(), any()) }
        }
    }
}
