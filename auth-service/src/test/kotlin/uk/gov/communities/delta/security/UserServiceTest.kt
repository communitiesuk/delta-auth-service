package uk.gov.communities.delta.security

import io.ktor.server.application.*
import io.ktor.test.dispatcher.*
import io.mockk.*
import kotlinx.coroutines.runBlocking
import org.hamcrest.CoreMatchers.containsString
import org.hamcrest.CoreMatchers.not
import org.hamcrest.MatcherAssert.assertThat
import org.junit.Assert
import org.junit.Before
import org.junit.Test
import uk.gov.communities.delta.auth.config.AzureADSSOClient
import uk.gov.communities.delta.auth.config.LDAPConfig
import uk.gov.communities.delta.auth.controllers.external.ResetPasswordException
import uk.gov.communities.delta.auth.services.*
import uk.gov.communities.delta.helper.testLdapUser
import java.time.Instant
import javax.naming.directory.Attributes
import javax.naming.directory.DirContext
import javax.naming.directory.ModificationItem
import javax.naming.ldap.InitialLdapContext
import kotlin.test.assertContains
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
    private val requiredSSOClient = mockk<AzureADSSOClient>()
    private val notRequiredSSOClient = mockk<AzureADSSOClient>()
    private val auditData = slot<String>()
    private val adminSession =
        OAuthSession(1, "adminUserCN", mockk(relaxed = true), "adminAccessToken", Instant.now(), "trace")

    @Before
    fun setupMocks() {
        modificationItems.clear()
        container.clear()
        contextBlock.clear()
        auditData.clear()
        coEvery { ldapServiceUserBind.useServiceUserBind(capture(contextBlock)) } coAnswers {
            contextBlock.captured(context)
        }
        coEvery { context.createSubcontext(userDN, capture(container)) } coAnswers { nothing }
        coEvery { context.modifyAttributes(userDN, capture(modificationItems)) } coAnswers { nothing }
        coEvery { requiredSSOClient.internalId } returns "abc-123"
        coEvery { requiredSSOClient.required } returns true
        coEvery { notRequiredSSOClient.internalId } returns "xyz-987"
        coEvery { notRequiredSSOClient.required } returns false
        coEvery { userAuditService.userSelfRegisterAudit(userCN, call, capture(auditData)) } just runs
        coEvery { userAuditService.userCreatedBySSOAudit(userCN, call, capture(auditData)) } just runs
        coEvery {
            userAuditService.ssoUserCreatedByAdminAudit(
                userCN,
                adminSession.userCn,
                call,
                capture(auditData)
            )
        } just runs
        coEvery {
            userAuditService.userCreatedByAdminAudit(
                userCN,
                adminSession.userCn,
                call,
                capture(auditData)
            )
        } just runs
    }

    @Test
    fun testCreateStandardUser() = testSuspend {
        userService.createUser(UserService.ADUser(ldapConfig, registration, null), null, null, call)
        verify(exactly = 1) { context.createSubcontext(userDN, any()) }
        // User has normal and disabled account
        assertEquals<String>("514", container.captured.get("userAccountControl").get() as String)
        // User has no password set yet
        assert(container.captured.get("unicodePwd") == null)
        assertContains(auditData.captured, "\"givenName\":\"${registration.firstName}\"")
        assertContains(auditData.captured, "\"sn\":\"${registration.lastName}\"")
        assertContains(auditData.captured, "\"mail\":\"${registration.emailAddress}\"")
        assertThat(auditData.captured, not(containsString("\"ssoClientInternalId\"")))
        assertThat(auditData.captured, not(containsString("\"azureObjectId\"")))
    }

    @Test
    fun testCreateStandardUserWithAllDetails() = testSuspend {
        val userDetails = UserService.DeltaUserDetails(
            "",
            false,
            userEmail,
            "testLast",
            "testFirst",
            "0123456789",
            "0987654321",
            "test position",
            null,
            arrayOf("datamart-delta-access-group-2", "datamart-delta-access-group-1"),
            arrayOf("datamart-delta-access-group-2"),
            mapOf("datamart-delta-access-group-2" to arrayOf("orgCode1", "orgCode2")),
            arrayOf("datamart-delta-role-1", "datamart-delta-role-2"),
            emptyArray(),
            arrayOf("orgCode1", "orgCode2"),
            "test comment",
            null
        )
        userService.createUser(UserService.ADUser(ldapConfig, userDetails, null), null, null, call)
        verify(exactly = 1) { context.createSubcontext(userDN, any()) }
        // User has normal and disabled account
        assertEquals<String>("514", container.captured.get("userAccountControl").get() as String)
        // User has no password set yet
        assert(container.captured.get("unicodePwd") == null)
        assertContains(auditData.captured, "\"givenName\":\"${userDetails.firstName}\"")
        assertContains(auditData.captured, "\"sn\":\"${userDetails.lastName}\"")
        assertContains(auditData.captured, "\"mail\":\"${userDetails.email}\"")
        assertContains(auditData.captured, "\"title\":\"${userDetails.position}\"")
        assertThat(auditData.captured, not(containsString("\"ssoClientInternalId\"")))
        assertThat(auditData.captured, not(containsString("\"azureObjectId\"")))
        // Check that reasonForAccess is not audited (blank in input data)
        assertThat(auditData.captured, not(containsString("description")))
    }

    @Test
    fun testAdminCreateStandardUser() = testSuspend {
        userService.createUser(UserService.ADUser(ldapConfig, registration, null), null, adminSession, call)
        verify(exactly = 1) { context.createSubcontext(userDN, any()) }
        // User has normal and disabled account
        assertEquals<String>("514", container.captured.get("userAccountControl").get() as String)
        // User has no password set yet
        assert(container.captured.get("unicodePwd") == null)
        assertContains(auditData.captured, "\"givenName\":\"${registration.firstName}\"")
        assertContains(auditData.captured, "\"sn\":\"${registration.lastName}\"")
        assertContains(auditData.captured, "\"mail\":\"${registration.emailAddress}\"")
        assertThat(auditData.captured, not(containsString("\"ssoClientInternalId\"")))
        assertThat(auditData.captured, not(containsString("\"azureObjectId\"")))
    }

    @Test
    fun testCreateSSOUser() = testSuspend {
        userService.createUser(
            UserService.ADUser(ldapConfig, registration, requiredSSOClient),
            requiredSSOClient,
            null,
            call
        )
        verify(exactly = 1) { context.createSubcontext(userDN, any()) }
        // User has normal and enabled account
        assertEquals<String>("512", container.captured.get("userAccountControl").get() as String)
        // User has had a password set at account creation
        assert(container.captured.get("unicodePwd").get() as ByteArray? != null)
        assertContains(auditData.captured, "\"givenName\":\"${registration.firstName}\"")
        assertContains(auditData.captured, "\"sn\":\"${registration.lastName}\"")
        assertContains(auditData.captured, "\"mail\":\"${registration.emailAddress}\"")
        assertContains(auditData.captured, "\"ssoClientInternalId\":\"${requiredSSOClient.internalId}\"")
        assertThat(auditData.captured, not(containsString("\"azureObjectId\"")))
    }

    @Test
    fun testAdminCreateSSOUser() = testSuspend {
        userService.createUser(
            UserService.ADUser(ldapConfig, registration, requiredSSOClient),
            requiredSSOClient,
            adminSession,
            call
        )
        verify(exactly = 1) { context.createSubcontext(userDN, any()) }
        // User has normal and enabled account
        assertEquals<String>("512", container.captured.get("userAccountControl").get() as String)
        // User has had a password set at account creation
        assert(container.captured.get("unicodePwd").get() as ByteArray? != null)
        assertContains(auditData.captured, "\"givenName\":\"${registration.firstName}\"")
        assertContains(auditData.captured, "\"sn\":\"${registration.lastName}\"")
        assertContains(auditData.captured, "\"mail\":\"${registration.emailAddress}\"")
        assertContains(auditData.captured, "\"ssoClientInternalId\":\"${requiredSSOClient.internalId}\"")
        assertThat(auditData.captured, not(containsString("\"azureObjectId\"")))
    }

    @Test
    fun testAdminCreateSSOUserWithAzureObjectID() = testSuspend {
        val azureObjectId = "azureObjectId"
        userService.createUser(
            UserService.ADUser(ldapConfig, registration, requiredSSOClient),
            requiredSSOClient,
            adminSession,
            call,
            azureObjectId
        )
        verify(exactly = 1) { context.createSubcontext(userDN, any()) }
        // User has normal and enabled account
        assertEquals<String>("512", container.captured.get("userAccountControl").get() as String)
        // User has had a password set at account creation
        assert(container.captured.get("unicodePwd").get() as ByteArray? != null)
        assertContains(auditData.captured, "\"givenName\":\"${registration.firstName}\"")
        assertContains(auditData.captured, "\"sn\":\"${registration.lastName}\"")
        assertContains(auditData.captured, "\"mail\":\"${registration.emailAddress}\"")
        assertContains(auditData.captured, "\"ssoClientInternalId\":\"${requiredSSOClient.internalId}\"")
        assertContains(auditData.captured, "\"azureObjectId\":\"${azureObjectId}\"")
    }

    @Test
    fun testCreateNotRequiredSSOUser() = testSuspend {
        userService.createUser(
            UserService.ADUser(ldapConfig, registration, notRequiredSSOClient),
            notRequiredSSOClient,
            null,
            call
        )
        verify(exactly = 1) { context.createSubcontext(userDN, any()) }
        // User has normal and disabled account
        assertEquals<String>("514", container.captured.get("userAccountControl").get() as String)
        // User has no password set yet
        assert(container.captured.get("unicodePwd") == null)
        assertContains(auditData.captured, "\"givenName\":\"${registration.firstName}\"")
        assertContains(auditData.captured, "\"sn\":\"${registration.lastName}\"")
        assertContains(auditData.captured, "\"mail\":\"${registration.emailAddress}\"")
        assertThat(auditData.captured, not(containsString("\"ssoClientInternalId\"")))
        assertThat(auditData.captured, not(containsString("\"azureObjectId\"")))
    }

    @Test
    fun testAdminCreateNotRequiredSSOUser() = testSuspend {
        userService.createUser(
            UserService.ADUser(ldapConfig, registration, notRequiredSSOClient),
            notRequiredSSOClient,
            adminSession,
            call
        )
        verify(exactly = 1) { context.createSubcontext(userDN, any()) }
        // User has normal and disabled account
        assertEquals<String>("514", container.captured.get("userAccountControl").get() as String)
        // User has no password set yet
        assert(container.captured.get("unicodePwd") == null)
        assertContains(auditData.captured, "\"givenName\":\"${registration.firstName}\"")
        assertContains(auditData.captured, "\"sn\":\"${registration.lastName}\"")
        assertContains(auditData.captured, "\"mail\":\"${registration.emailAddress}\"")
        assertThat(auditData.captured, not(containsString("\"ssoClientInternalId\"")))
        assertThat(auditData.captured, not(containsString("\"azureObjectId\"")))
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
        val adUser = UserService.ADUser(ldapConfig, registration, requiredSSOClient)
        assertEquals(18 * 8 / 6, adUser.password!!.length)
    }
}
