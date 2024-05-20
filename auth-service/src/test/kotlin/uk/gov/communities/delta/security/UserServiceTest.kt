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
import uk.gov.communities.delta.auth.controllers.internal.DeltaUserDetailsRequest
import uk.gov.communities.delta.auth.repositories.LdapRepository
import uk.gov.communities.delta.auth.repositories.LdapUser
import uk.gov.communities.delta.auth.services.*
import uk.gov.communities.delta.helper.testLdapUser
import java.time.Instant
import java.util.*
import javax.naming.directory.Attributes
import javax.naming.directory.BasicAttribute
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
    private val ldapRepository = mockk<LdapRepository>()
    private val userService =
        UserService(ldapServiceUserBind, userLookupService, userAuditService, ldapConfig, ldapRepository)
    private val user = testLdapUser(
        dn = String.format(deltaUserDnFormat, "user!example.com"),
        cn = "user!example.com",
        email = "user@example.com",
        memberOfCNs = listOf("group-1", "group-2"),
        comment = "test comment",
    )
    private val registration = Registration("Test", "User", user.email!!)
    private val container = slot<Attributes>()
    private val modificationItems = slot<Array<ModificationItem>>()
    private val context = mockk<InitialLdapContext>()
    private val contextBlock = slot<(InitialLdapContext) -> LdapUser>()

    private val call = mockk<ApplicationCall>()
    private val requiredSSOClient = mockk<AzureADSSOClient>()
    private val notRequiredSSOClient = mockk<AzureADSSOClient>()
    private val auditData = slot<String>()
    private val adminSession =
        OAuthSession(
            1,
            "adminUserCN",
            UUID.randomUUID(),
            mockk(relaxed = true),
            "adminAccessToken",
            Instant.now(),
            "trace",
            false
        )
    private val testUserDetails = DeltaUserDetailsRequest(
        user.email!!,
        false,
        user.email!!,
        "testLast",
        "testFirst",
        "0123456789",
        "0987654321",
        "test position",
        null,
        listOf("datamart-delta-access-group-1", "datamart-delta-access-group-2"),
        listOf("datamart-delta-access-group-2"),
        mapOf("datamart-delta-access-group-2" to listOf("orgCode1", "orgCode2")),
        listOf("datamart-delta-role-1", "datamart-delta-role-2"),
        emptyList(),
        listOf("orgCode1", "orgCode2"),
        "test comment",
        null
    )

    @Before
    fun setupMocks() {
        modificationItems.clear()
        container.clear()
        contextBlock.clear()
        auditData.clear()
        coEvery { ldapServiceUserBind.useServiceUserBind(capture(contextBlock)) } coAnswers {
            contextBlock.captured(context)
        }
        coEvery { context.createSubcontext(user.dn, capture(container)) } coAnswers { nothing }
        coEvery { context.modifyAttributes(user.dn, capture(modificationItems)) } coAnswers { nothing }
        coEvery { ldapRepository.mapUserFromContext(context, user.dn) } returns user
        coEvery { requiredSSOClient.internalId } returns "abc-123"
        coEvery { requiredSSOClient.required } returns true
        coEvery { notRequiredSSOClient.internalId } returns "xyz-987"
        coEvery { notRequiredSSOClient.required } returns false
        coEvery { userAuditService.userSelfRegisterAudit(user.cn, user.getUUID(), call, capture(auditData)) } just runs
        coEvery { userAuditService.userCreatedBySSOAudit(user.cn, user.getUUID(), call, capture(auditData)) } just runs
        coEvery {
            userAuditService.ssoUserCreatedByAdminAudit(
                user.cn, user.getUUID(), adminSession.userCn, adminSession.userGUID!!, call, capture(auditData)
            )
        } just runs
        coEvery {
            userAuditService.userCreatedByAdminAudit(
                user.cn, user.getUUID(), adminSession.userCn, adminSession.userGUID!!, call, capture(auditData)
            )
        } just runs
        coEvery {
            userAuditService.userUpdateByAdminAudit(
                user.cn, user.getUUID(), adminSession.userCn, adminSession.userGUID!!, call, capture(auditData)
            )
        } just runs
        coEvery { userLookupService.lookupUserByGUID(user.getUUID()) } returns user
    }

    @Test
    fun testCreateStandardUser() = testSuspend {
        userService.createUser(UserService.ADUser(ldapConfig, registration, null), null, null, call)
        verify(exactly = 1) { context.createSubcontext(user.dn, any()) }
        // User has normal and disabled account
        assertEquals<String>("514", container.captured.get("userAccountControl").get() as String)
        // User has no password set yet
        assert(container.captured.get("unicodePwd") == null)
        assertContains(auditData.captured, "\"givenName\":\"${registration.firstName}\"")
        assertContains(auditData.captured, "\"sn\":\"${registration.lastName}\"")
        assertContains(auditData.captured, "\"mail\":\"${registration.emailAddress}\"")
        assertThat(auditData.captured, not(containsString("\"SettingPassword\"")))
        assertThat(auditData.captured, not(containsString("\"ssoClientInternalId\"")))
        assertThat(auditData.captured, not(containsString("\"azureObjectId\"")))
    }

    @Test
    fun testCreateStandardUserWithAllDetails() = testSuspend {
        userService.createUser(UserService.ADUser(ldapConfig, testUserDetails, null), null, null, call)
        verify(exactly = 1) { context.createSubcontext(user.dn, any()) }
        // User has normal and disabled account
        assertEquals<String>("514", container.captured.get("userAccountControl").get() as String)
        // User has no password set yet
        assert(container.captured.get("unicodePwd") == null)
        assertContains(auditData.captured, "\"givenName\":\"${testUserDetails.firstName}\"")
        assertContains(auditData.captured, "\"sn\":\"${testUserDetails.lastName}\"")
        assertContains(auditData.captured, "\"mail\":\"${testUserDetails.email}\"")
        assertContains(auditData.captured, "\"title\":\"${testUserDetails.position}\"")
        assertThat(auditData.captured, not(containsString("\"SettingPassword\"")))
        assertThat(auditData.captured, not(containsString("\"ssoClientInternalId\"")))
        assertThat(auditData.captured, not(containsString("\"azureObjectId\"")))
        // Check that reasonForAccess is not audited (blank in input data)
        assertThat(auditData.captured, not(containsString("description")))
    }

    @Test
    fun testAdminCreateStandardUser() = testSuspend {
        userService.createUser(UserService.ADUser(ldapConfig, registration, null), null, adminSession, call)
        verify(exactly = 1) { context.createSubcontext(user.dn, any()) }
        // User has normal and disabled account
        assertEquals<String>("514", container.captured.get("userAccountControl").get() as String)
        // User has no password set yet
        assert(container.captured.get("unicodePwd") == null)
        assertContains(auditData.captured, "\"givenName\":\"${registration.firstName}\"")
        assertContains(auditData.captured, "\"sn\":\"${registration.lastName}\"")
        assertContains(auditData.captured, "\"mail\":\"${registration.emailAddress}\"")
        assertThat(auditData.captured, not(containsString("\"SettingPassword\"")))
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
        verify(exactly = 1) { context.createSubcontext(user.dn, any()) }
        // User has normal and enabled account
        assertEquals<String>("512", container.captured.get("userAccountControl").get() as String)
        // User has had a password set at account creation
        assert(container.captured.get("unicodePwd").get() as ByteArray? != null)
        assertContains(auditData.captured, "\"givenName\":\"${registration.firstName}\"")
        assertContains(auditData.captured, "\"sn\":\"${registration.lastName}\"")
        assertContains(auditData.captured, "\"mail\":\"${registration.emailAddress}\"")
        assertContains(auditData.captured, "\"ssoClientInternalId\":\"${requiredSSOClient.internalId}\"")
        assertContains(auditData.captured, "\"SettingPassword\":\"true\"")
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
        verify(exactly = 1) { context.createSubcontext(user.dn, any()) }
        // User has normal and enabled account
        assertEquals<String>("512", container.captured.get("userAccountControl").get() as String)
        // User has had a password set at account creation
        assert(container.captured.get("unicodePwd").get() as ByteArray? != null)
        assertContains(auditData.captured, "\"givenName\":\"${registration.firstName}\"")
        assertContains(auditData.captured, "\"sn\":\"${registration.lastName}\"")
        assertContains(auditData.captured, "\"mail\":\"${registration.emailAddress}\"")
        assertContains(auditData.captured, "\"ssoClientInternalId\":\"${requiredSSOClient.internalId}\"")
        assertContains(auditData.captured, "\"SettingPassword\":\"true\"")
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
        verify(exactly = 1) { context.createSubcontext(user.dn, any()) }
        // User has normal and enabled account
        assertEquals<String>("512", container.captured.get("userAccountControl").get() as String)
        // User has had a password set at account creation
        assert(container.captured.get("unicodePwd").get() as ByteArray? != null)
        assertContains(auditData.captured, "\"givenName\":\"${registration.firstName}\"")
        assertContains(auditData.captured, "\"sn\":\"${registration.lastName}\"")
        assertContains(auditData.captured, "\"mail\":\"${registration.emailAddress}\"")
        assertContains(auditData.captured, "\"ssoClientInternalId\":\"${requiredSSOClient.internalId}\"")
        assertContains(auditData.captured, "\"azureObjectId\":\"${azureObjectId}\"")
        assertContains(auditData.captured, "\"SettingPassword\":\"true\"")
    }

    @Test
    fun testCreateNotRequiredSSOUser() = testSuspend {
        userService.createUser(
            UserService.ADUser(ldapConfig, registration, notRequiredSSOClient),
            notRequiredSSOClient,
            null,
            call
        )
        verify(exactly = 1) { context.createSubcontext(user.dn, any()) }
        // User has normal and disabled account
        assertEquals<String>("514", container.captured.get("userAccountControl").get() as String)
        // User has no password set yet
        assert(container.captured.get("unicodePwd") == null)
        assertContains(auditData.captured, "\"givenName\":\"${registration.firstName}\"")
        assertContains(auditData.captured, "\"sn\":\"${registration.lastName}\"")
        assertContains(auditData.captured, "\"mail\":\"${registration.emailAddress}\"")
        assertThat(auditData.captured, not(containsString("\"SettingPassword\"")))
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
        verify(exactly = 1) { context.createSubcontext(user.dn, any()) }
        // User has normal and disabled account
        assertEquals<String>("514", container.captured.get("userAccountControl").get() as String)
        // User has no password set yet
        assert(container.captured.get("unicodePwd") == null)
        assertContains(auditData.captured, "\"givenName\":\"${registration.firstName}\"")
        assertContains(auditData.captured, "\"sn\":\"${registration.lastName}\"")
        assertContains(auditData.captured, "\"mail\":\"${registration.emailAddress}\"")
        assertThat(auditData.captured, not(containsString("\"SettingPassword\"")))
        assertThat(auditData.captured, not(containsString("\"ssoClientInternalId\"")))
        assertThat(auditData.captured, not(containsString("\"azureObjectId\"")))
    }

    @Test
    fun testAdminUpdateUser() = testSuspend {
        val modificationItems = arrayOf(
            ModificationItem(DirContext.REMOVE_ATTRIBUTE, BasicAttribute("comment")),
            ModificationItem(DirContext.ADD_ATTRIBUTE, BasicAttribute("description", "test reasonForAccess")),
            ModificationItem(DirContext.REPLACE_ATTRIBUTE, BasicAttribute("sn", "test new surname"))
        )
        userService.updateUser(user, modificationItems, adminSession, userLookupService, call)
        verify(exactly = 1) { context.modifyAttributes(user.dn, modificationItems) }
        assertEquals(
            auditData.captured,
            "{\"comment\":\"\",\"description\":\"test reasonForAccess\",\"sn\":\"test new surname\"}"
        )
    }

    @Test
    fun testSetUserPassword() = testSuspend {
        userService.setPasswordAndEnable(user.dn, "TestPassword")
        verify(exactly = 1) { context.modifyAttributes(user.dn, any()) }
        // User has normal and enabled account
        assertEquals(DirContext.REPLACE_ATTRIBUTE, modificationItems.captured[1].modificationOp)
        assertEquals("512", modificationItems.captured[1].attribute.get())
        // User has a password set
        assert(modificationItems.captured[0].attribute.get() as ByteArray? != null)
    }

    @Test
    fun testResetUserPassword() = testSuspend {
        coEvery { userLookupService.lookupUserByGUID(user.getUUID()) } returns user
        userService.resetPassword(user.getUUID(), "TestPassword")
        verify(exactly = 1) { context.modifyAttributes(user.dn, any()) }
        // User is unlocked
        assertEquals(DirContext.REPLACE_ATTRIBUTE, modificationItems.captured[1].modificationOp)
        assertEquals("lockoutTime", modificationItems.captured[1].attribute.id)
        assertEquals("0", modificationItems.captured[1].attribute.get())
        // User has a password set
        assert(modificationItems.captured[0].attribute.get() as ByteArray? != null)
    }

    @Test
    fun testResetUserPasswordDisabledUser() = testSuspend {
        val disabledUser = testLdapUser(accountEnabled = false)
        coEvery { userLookupService.lookupUserByGUID(disabledUser.getUUID()) } returns disabledUser
        Assert.assertThrows(ResetPasswordException::class.java) {
            runBlocking {
                userService.resetPassword(disabledUser.getUUID(), "TestPassword")
            }
        }
        verify(exactly = 0) { context.modifyAttributes(disabledUser.dn, any()) }
    }

    @Test
    fun testPasswordCreation() = testSuspend {
        val adUser = UserService.ADUser(ldapConfig, registration, requiredSSOClient)
        assertEquals(18 * 8 / 6, adUser.password!!.length)
    }
}
