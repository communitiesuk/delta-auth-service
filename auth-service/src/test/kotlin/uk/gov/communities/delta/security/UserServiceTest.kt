package uk.gov.communities.delta.security

import io.ktor.server.application.*
import io.ktor.test.dispatcher.*
import io.mockk.*
import kotlinx.coroutines.runBlocking
import org.junit.Assert
import org.junit.Before
import org.junit.Test
import uk.gov.communities.delta.auth.config.AzureADSSOClient
import uk.gov.communities.delta.auth.config.LDAPConfig
import uk.gov.communities.delta.auth.controllers.external.ResetPasswordException
import uk.gov.communities.delta.auth.services.*
import uk.gov.communities.delta.helper.testLdapUser
import javax.naming.directory.Attributes
import javax.naming.directory.DirContext
import javax.naming.directory.ModificationItem
import javax.naming.ldap.InitialLdapContext
import kotlin.test.assertEquals

class UserServiceTest {
    private val ldapServiceUserBind = mockk<LdapServiceUserBind>()
    private val deltaUserDnFormat = "CN=%s"
    private val ldapConfig = LDAPConfig("testInvalidUrl", "", deltaUserDnFormat, "", "", "", "", "", "")
    private val userLookupService = mockk<UserLookupService>()
    private val userAuditService = mockk<UserAuditService>()
    private val userService = UserService(ldapServiceUserBind, userLookupService, userAuditService)
    private val userEmail = "user@example.com"
    private val registration = Registration("Test", "User", userEmail)
    private val container = slot<Attributes>()
    private val modificationItems = slot<Array<ModificationItem>>()
    private val context = mockk<InitialLdapContext>()
    private val contextBlock = slot<(InitialLdapContext) -> Unit>()
    private val userCN = LDAPConfig.emailToCN(userEmail)
    private val userDN = String.format(deltaUserDnFormat, userCN)
    private val call = mockk<ApplicationCall>()
    private val ssoClient = mockk<AzureADSSOClient>()

    @Before
    fun setupMocks() {
        modificationItems.clear()
        contextBlock.clear()
        coEvery { ldapServiceUserBind.useServiceUserBind(capture(contextBlock)) } coAnswers {
            contextBlock.captured(context)
        }
        coEvery { context.createSubcontext(userDN, capture(container)) } coAnswers { nothing }
        coEvery { context.modifyAttributes(userDN, capture(modificationItems)) } coAnswers { nothing }
        coEvery { userAuditService.userCreatedBySSOAudit(any(), call, any()) } coAnswers { nothing }
        coEvery { userAuditService.userSelfRegisterAudit(any(), call, any()) } just runs
        coEvery { ssoClient.internalId } returns "abc-123"
    }

    @Test
    fun testSuccessfulCreateStandardUser() = testSuspend {
        userService.createUser(UserService.ADUser(ldapConfig, registration, null), null, null, call)
        verify(exactly = 1) { context.createSubcontext(userDN, any()) }
        // User has normal and disabled account
        assertEquals<String>("514", container.captured.get("userAccountControl").get() as String)
        // User has no password set yet
        assert(container.captured.get("unicodePwd") == null)
    }

    @Test
    fun testSuccessfulCreateSSOUser() = testSuspend {
        userService.createUser(UserService.ADUser(ldapConfig, registration, ssoClient), ssoClient, null, call)
        verify(exactly = 1) { context.createSubcontext(userDN, any()) }
        // User has normal and enabled account
        assertEquals<String>("512", container.captured.get("userAccountControl").get() as String)
        // User has had a password set at account creation
        assert(container.captured.get("unicodePwd").get() as ByteArray? != null)
    }

    @Test
    fun testSetUserPassword() = testSuspend {
        userService.setPassword(userDN, "TestPassword")
        verify(exactly = 1) { context.modifyAttributes(userDN, any()) }
        // User has normal and enabled account
        assertEquals(DirContext.REPLACE_ATTRIBUTE, modificationItems.captured[1].modificationOp)
        assertEquals("512", modificationItems.captured[1].attribute.get())
        // User has a password set
        assert(modificationItems.captured[0].attribute.get() as ByteArray? != null)
    }

    @Test
    fun testResetUserPassword() = testSuspend {
        coEvery { userLookupService.lookupUserByDN(userDN) } returns testLdapUser(accountEnabled = true)
        userService.resetPassword(userDN, "TestPassword")
        verify(exactly = 1) { context.modifyAttributes(userDN, any()) }
        // User is unlocked
        assertEquals(DirContext.REPLACE_ATTRIBUTE, modificationItems.captured[1].modificationOp)
        assertEquals("lockoutTime", modificationItems.captured[1].attribute.id)
        assertEquals("0", modificationItems.captured[1].attribute.get())
        // User has a password set
        assert(modificationItems.captured[0].attribute.get() as ByteArray? != null)
    }

    @Test
    fun testResetUserPasswordDisabledUser() = testSuspend {
        coEvery { userLookupService.lookupUserByDN(userDN) } returns testLdapUser(accountEnabled = false)
        Assert.assertThrows(ResetPasswordException::class.java) {
            runBlocking {
                userService.resetPassword(userDN, "TestPassword")
            }
        }
        verify(exactly = 0) { context.modifyAttributes(userDN, any()) }
    }

    @Test
    fun testPasswordCreation() = testSuspend {
        val adUser = UserService.ADUser(ldapConfig, registration, ssoClient)
        assertEquals(18 * 8 / 6, adUser.password!!.length)
    }
}
