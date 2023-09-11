package uk.gov.communities.delta.security

import io.ktor.test.dispatcher.*
import io.mockk.coEvery
import io.mockk.mockk
import io.mockk.slot
import io.mockk.verify
import org.junit.Before
import org.junit.Test
import uk.gov.communities.delta.auth.config.LDAPConfig
import uk.gov.communities.delta.auth.services.LdapService
import uk.gov.communities.delta.auth.services.Registration
import uk.gov.communities.delta.auth.services.UserService
import javax.naming.directory.Attributes
import javax.naming.directory.DirContext
import javax.naming.directory.ModificationItem
import javax.naming.ldap.InitialLdapContext
import kotlin.test.assertEquals

class UserServiceTest {
    private val ldapService = mockk<LdapService>()
    private val userService = UserService(ldapService)
    private val deltaUserDnFormat = "CN=%s"
    private val ldapConfig = LDAPConfig("testInvalidUrl", "", deltaUserDnFormat, "", "", "", "", "", "")
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
    fun testPasswordCreation() = testSuspend {
        val adUser = UserService.ADUser(registration, true, ldapConfig)
        assertEquals(18 * 8 / 6, adUser.password!!.length)
    }
}
