package uk.gov.communities.delta.security

import io.ktor.server.application.*
import io.ktor.server.auth.*
import io.ktor.test.dispatcher.*
import io.mockk.*
import org.junit.Before
import org.junit.Test
import uk.gov.communities.delta.auth.config.AzureADSSOClient
import uk.gov.communities.delta.auth.config.DeltaConfig
import uk.gov.communities.delta.auth.config.EmailConfig
import uk.gov.communities.delta.auth.config.LDAPConfig
import uk.gov.communities.delta.auth.services.*
import uk.gov.communities.delta.helper.testLdapUser
import kotlin.test.assertTrue

class RegistrationServiceTest {
    private val deltaConfig = DeltaConfig.fromEnv()
    private val setPasswordTokenService = mockk<SetPasswordTokenService>()
    private val emailService = mockk<EmailService>()
    private val userService = mockk<UserService>()
    private val userLookupService = mockk<UserLookupService>()
    private val groupService = mockk<GroupService>()
    private val call = mockk<ApplicationCall>()
    private val requiredSSOClient = mockk<AzureADSSOClient>()
    private val notRequiredSSOClient = mockk<AzureADSSOClient>()
    private val orgCode = "E12345"
    val user = testLdapUser(cn = "user!example.com", email = "user@example.com")
    private val anotherOrgCode = orgCode + "2"
    private val retiredOrganisation = Organisation(orgCode, "Test org", "2023-09-30Z")

    private val registrationService = RegistrationService(
        deltaConfig,
        EmailConfig.fromEnv(),
        LDAPConfig("testInvalidUrl", "", "", "", "", "", "", "", ""),
        setPasswordTokenService,
        emailService,
        userService,
        userLookupService,
        groupService
    )

    @Before
    fun setup() {
        coEvery { userLookupService.userIfExists(any()) } returns null
        coEvery { groupService.addUserToGroup(any(), any(), any(), null, any()) } just runs
        coEvery { userService.createUser(any(), any(), any(), any(), any()) } returns testLdapUser()
        coEvery { setPasswordTokenService.createToken(any(), any()) } returns "token"
        coEvery { call.principal<OAuthSession>() } returns null
        coEvery { requiredSSOClient.required } returns true
        coEvery { notRequiredSSOClient.required } returns false
    }

    @Test
    fun testRegisteringNewStandardUser() = testSuspend {
        val registrationResult = registrationService.register(
            Registration(user.firstName, user.lastName, user.email!!),
            listOf(Organisation(orgCode, "Test org")),
            call,
        )
        coVerify(exactly = 1) { userService.createUser(any(), null, null, call) }
        coVerify(exactly = 1) {
            groupService.addUserToGroup(any(), DeltaConfig.DATAMART_DELTA_REPORT_USERS, any(), null, userLookupService)
        }
        coVerify(exactly = 1) {
            groupService.addUserToGroup(any(), DeltaConfig.DATAMART_DELTA_USER, any(), null, userLookupService)
        }
        coVerify(exactly = 1) { groupService.addUserToGroup(any(), groupName(orgCode), any(), null, userLookupService) }
        coVerify(exactly = 3) { groupService.addUserToGroup(any(), any(), any(), null, userLookupService) }
        coVerify(exactly = 1) { setPasswordTokenService.createToken(any(), any()) }
        assertTrue(registrationResult is RegistrationService.UserCreated)
    }

    @Test
    fun testSSOUserRegistration() = testSuspend {
        val registrationResult = registrationService.register(
            Registration(user.firstName, user.lastName, user.email!!),
            listOf(Organisation(orgCode, "Test org")),
            call,
            requiredSSOClient
        )
        coVerify(exactly = 1) { userService.createUser(any(), requiredSSOClient, null, call) }
        coVerify(exactly = 1) {
            groupService.addUserToGroup(any(), DeltaConfig.DATAMART_DELTA_REPORT_USERS, any(), null, userLookupService)
        }
        coVerify(exactly = 1) {
            groupService.addUserToGroup(any(), DeltaConfig.DATAMART_DELTA_USER, any(), null, userLookupService)
        }
        coVerify(exactly = 1) { groupService.addUserToGroup(any(), groupName(orgCode), any(), null, userLookupService) }
        coVerify(exactly = 3) { groupService.addUserToGroup(any(), any(), any(), null, userLookupService) }
        coVerify(exactly = 0) { setPasswordTokenService.createToken(any(), any()) }
        assertTrue(registrationResult is RegistrationService.SSOUserCreated)
    }

    @Test
    fun testSSOUserRegistrationWithAzureObjectID() = testSuspend {
        val azureId = "testAzureId"
        val registrationResult = registrationService.register(
            Registration(user.firstName, user.lastName, user.email!!),
            listOf(Organisation(orgCode, "Test org")),
            call,
            requiredSSOClient,
            azureId
        )
        coVerify(exactly = 1) { userService.createUser(any(), requiredSSOClient, null, call, azureId) }
        coVerify(exactly = 1) {
            groupService.addUserToGroup(any(), DeltaConfig.DATAMART_DELTA_REPORT_USERS, any(), null, userLookupService)
        }
        coVerify(exactly = 1) {
            groupService.addUserToGroup(any(), DeltaConfig.DATAMART_DELTA_USER, any(), null, userLookupService)
        }
        coVerify(exactly = 1) { groupService.addUserToGroup(any(), groupName(orgCode), any(), null, userLookupService) }
        coVerify(exactly = 3) { groupService.addUserToGroup(any(), any(), any(), null, userLookupService) }
        coVerify(exactly = 0) { setPasswordTokenService.createToken(any(), any()) }
        assertTrue(registrationResult is RegistrationService.SSOUserCreated)
    }

    @Test
    fun testNotRequiredSSOUserRegistration() = testSuspend {
        val registrationResult = registrationService.register(
            Registration(user.firstName, user.lastName, user.email!!),
            listOf(Organisation(orgCode, "Test org")),
            call,
            notRequiredSSOClient
        )
        coVerify(exactly = 1) { userService.createUser(any(), notRequiredSSOClient, null, call) }
        coVerify(exactly = 1) {
            groupService.addUserToGroup(any(), DeltaConfig.DATAMART_DELTA_REPORT_USERS, any(), null, userLookupService)
        }
        coVerify(exactly = 1) {
            groupService.addUserToGroup(any(), DeltaConfig.DATAMART_DELTA_USER, any(), null, userLookupService)
        }
        coVerify(exactly = 1) { groupService.addUserToGroup(any(), groupName(orgCode), any(), null, userLookupService) }
        coVerify(exactly = 3) { groupService.addUserToGroup(any(), any(), any(), null, userLookupService) }
        coVerify(exactly = 1) { setPasswordTokenService.createToken(any(), any()) }
        assertTrue(registrationResult is RegistrationService.UserCreated)
    }

    @Test
    fun testRegisteringExistingStandardUser() = testSuspend {
        coEvery { userLookupService.userIfExists(user.email!!) } returns user
        val registrationResult = registrationService.register(
            Registration(user.firstName, user.lastName, user.email!!),
            listOf(Organisation(orgCode, "Test org")),
            call,
            requiredSSOClient
        )
        assertTrue(registrationResult is RegistrationService.UserAlreadyExists)
        coVerify(exactly = 0) { userService.createUser(any(), any(), any(), any()) }
        coVerify(exactly = 0) { groupService.addUserToGroup(any(), any(), any(), null, userLookupService) }
        coVerify(exactly = 0) { setPasswordTokenService.createToken(any(), any()) }
    }

    @Test
    fun testStandardUserInMultipleOrg() = testSuspend {
        val registrationResult = registrationService.register(
            Registration(user.firstName, user.lastName, user.email!!),
            listOf(Organisation(orgCode, "Test org"), Organisation(anotherOrgCode, name = "Another org")),
            call,
        )
        coVerify(exactly = 1) { userService.createUser(any(), null, null, call) }
        coVerify(exactly = 1) {
            groupService.addUserToGroup(any(), DeltaConfig.DATAMART_DELTA_REPORT_USERS, any(), null, userLookupService)
        }
        coVerify(exactly = 1) {
            groupService.addUserToGroup(any(), DeltaConfig.DATAMART_DELTA_USER, any(), null, userLookupService)
        }
        coVerify(exactly = 1) { groupService.addUserToGroup(any(), groupName(orgCode), any(), null, userLookupService) }
        coVerify(exactly = 1) {
            groupService.addUserToGroup(any(), groupName(anotherOrgCode), any(), null, userLookupService)
        }
        coVerify(exactly = 4) { groupService.addUserToGroup(any(), any(), any(), null, userLookupService) }
        coVerify(exactly = 1) { setPasswordTokenService.createToken(any(), any()) }
        assertTrue(registrationResult is RegistrationService.UserCreated)
    }

    @Test
    fun testStandardUserInRetiredAndNotRetiredOrg() = testSuspend {
        val registrationResult = registrationService.register(
            Registration(user.firstName, user.lastName, user.email!!),
            listOf(retiredOrganisation, Organisation(anotherOrgCode, name = "Another org")),
            call,
        )
        coVerify(exactly = 1) { userService.createUser(any(), null, null, call) }
        coVerify(exactly = 1) {
            groupService.addUserToGroup(any(), DeltaConfig.DATAMART_DELTA_REPORT_USERS, any(), null, userLookupService)
        }
        coVerify(exactly = 1) {
            groupService.addUserToGroup(any(), DeltaConfig.DATAMART_DELTA_USER, any(), null, userLookupService)
        }
        coVerify(exactly = 0) { groupService.addUserToGroup(any(), groupName(orgCode), any(), null, userLookupService) }
        coVerify(exactly = 1) {
            groupService.addUserToGroup(any(), groupName(anotherOrgCode), any(), null, userLookupService)
        }
        coVerify(exactly = 3) { groupService.addUserToGroup(any(), any(), any(), null, userLookupService) }
        coVerify(exactly = 1) { setPasswordTokenService.createToken(any(), any()) }
        assertTrue(registrationResult is RegistrationService.UserCreated)
    }

    private fun groupName(orgCode: String) = String.format("%s-%s", DeltaConfig.DATAMART_DELTA_USER, orgCode)
}
