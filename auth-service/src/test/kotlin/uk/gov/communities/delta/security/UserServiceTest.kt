package uk.gov.communities.delta.security

import io.ktor.test.dispatcher.*
import io.mockk.coEvery
import io.mockk.mockk
import io.mockk.slot
import io.mockk.verify
import kotlinx.coroutines.runBlocking
import org.junit.Assert
import org.junit.Before
import org.junit.Test
import uk.gov.communities.delta.auth.config.LDAPConfig
import uk.gov.communities.delta.auth.controllers.external.ResetPasswordException
import uk.gov.communities.delta.auth.services.LdapService
import uk.gov.communities.delta.auth.services.Registration
import uk.gov.communities.delta.auth.services.UserLookupService
import uk.gov.communities.delta.auth.services.UserService
import uk.gov.communities.delta.helper.testLdapUser
import javax.naming.directory.Attributes
import javax.naming.directory.DirContext
import javax.naming.directory.ModificationItem
import javax.naming.ldap.InitialLdapContext
import kotlin.test.assertEquals

class UserServiceTest {
    private val ldapService = mockk<LdapService>()
    private val deltaUserDnFormat = "CN=%s"
    private val ldapConfig = LDAPConfig("testInvalidUrl", "", deltaUserDnFormat, "", "", "", "", "", "")
    private val userLookupService = mockk<UserLookupService>()
    private val userService = UserService(ldapService, userLookupService)
    private val userEmail = "user@example.com"
    private val registration = Registration("Test", "User", userEmail)
    private val container = slot<Attributes>()
    private val modificationItems = slot<Array<ModificationItem>>()
    private val context = mockk<InitialLdapContext>()
    private val contextBlock = slot<(InitialLdapContext) -> Unit>()
    private val userCN = userEmail.replace("@", "!")
    private val userDN = String.format(deltaUserDnFormat, userCN)

    @Before
    fun setupMocks() {
        modificationItems.clear()
        contextBlock.clear()
        coEvery { ldapService.useServiceUserBind(capture(contextBlock)) } coAnswers { contextBlock.captured(context) }
        coEvery { context.createSubcontext(userDN, capture(container)) } coAnswers { nothing }
        coEvery { context.modifyAttributes(userDN, capture(modificationItems)) } coAnswers { nothing }
    }

    @Test
    fun testSuccessfulCreateStandardUser() = testSuspend {
        userService.createUser(UserService.ADUser(registration, false, ldapConfig))
        verify(exactly = 1) { context.createSubcontext(userDN, any()) }
        // User has normal and disabled account
        assertEquals<String>("514", container.captured.get("userAccountControl").get() as String)
        // User has no password set yet
        assert(container.captured.get("unicodePwd") == null)
    }

    @Test
    fun testSuccessfulCreateSSOUser() = testSuspend {
        userService.createUser(UserService.ADUser(registration, true, ldapConfig))
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
        val adUser = UserService.ADUser(registration, true, ldapConfig)
        assertEquals(18 * 8 / 6, adUser.password!!.length)
    }
}
