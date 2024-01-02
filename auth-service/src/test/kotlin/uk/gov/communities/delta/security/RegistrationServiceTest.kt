package uk.gov.communities.delta.security

import io.ktor.test.dispatcher.*
import io.mockk.*
import org.junit.Before
import org.junit.Test
import uk.gov.communities.delta.auth.config.AuthServiceConfig
import uk.gov.communities.delta.auth.config.DeltaConfig
import uk.gov.communities.delta.auth.config.EmailConfig
import uk.gov.communities.delta.auth.config.LDAPConfig
import uk.gov.communities.delta.auth.services.*
import kotlin.test.assertTrue

class RegistrationServiceTest {
    private val deltaConfig = DeltaConfig.fromEnv()
    private val authServiceConfig = AuthServiceConfig("http://localhost", null)
    private val setPasswordTokenService = mockk<SetPasswordTokenService>()
    private val emailService = mockk<EmailService>()
    private val userService = mockk<UserService>()
    private val userLookupService = mockk<UserLookupService>()
    private val groupService = mockk<GroupService>()
    private val orgCode = "E12345"
    private val userCN = "user!example.com"
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
        coEvery { userLookupService.userExists(any()) } returns false
        coEvery { groupService.addUserToGroup(any(), any()) } just runs
        coEvery { userService.createUser(any()) } just runs
        coEvery { setPasswordTokenService.createToken(any()) } returns "token"
    }

    @Test
    fun testRegisteringNewStandardUser() = testSuspend {
        val registrationResult = registrationService.register(
            Registration("Test", "User", "user@example.com"),
            listOf(Organisation(orgCode, "Test org")),
        )
        coVerify(exactly = 1) { userService.createUser(any()) }
        coVerify(exactly = 1) { groupService.addUserToGroup(any(), deltaConfig.datamartDeltaReportUsers) }
        coVerify(exactly = 1) { groupService.addUserToGroup(any(), deltaConfig.datamartDeltaUser) }
        coVerify(exactly = 1) { groupService.addUserToGroup(any(), groupName(orgCode)) }
        coVerify(exactly = 3) { groupService.addUserToGroup(any(), any()) }
        coVerify(exactly = 1) { setPasswordTokenService.createToken(any()) }
        assertTrue(registrationResult is RegistrationService.UserCreated)
    }

    @Test
    fun testSSOUserRegistration() = testSuspend {
        val registrationResult = registrationService.register(
            Registration("Test", "User", "user@example.com"),
            listOf(Organisation(orgCode, "Test org")),
            true
        )
        coVerify(exactly = 1) { userService.createUser(any()) }
        coVerify(exactly = 1) { groupService.addUserToGroup(any(), deltaConfig.datamartDeltaReportUsers) }
        coVerify(exactly = 1) { groupService.addUserToGroup(any(), deltaConfig.datamartDeltaUser) }
        coVerify(exactly = 1) { groupService.addUserToGroup(any(), groupName(orgCode)) }
        coVerify(exactly = 3) { groupService.addUserToGroup(any(), any()) }
        coVerify(exactly = 0) { setPasswordTokenService.createToken(any()) }
        assertTrue(registrationResult is RegistrationService.SSOUserCreated)
    }

    @Test
    fun testRegisteringExistingStandardUser() = testSuspend {
        coEvery { userLookupService.userExists(userCN) } returns true
        val registrationResult = registrationService.register(
            Registration("Test", "User", "user@example.com"),
            listOf(Organisation(orgCode, "Test org")),
            true
        )
        assertTrue(registrationResult is RegistrationService.UserAlreadyExists)
        coVerify(exactly = 0) { userService.createUser(any()) }
        coVerify(exactly = 0) { groupService.addUserToGroup(any(), any()) }
        coVerify(exactly = 0) { setPasswordTokenService.createToken(any()) }
    }

    @Test
    fun testStandardUserInMultipleOrg() = testSuspend {
        val registrationResult = registrationService.register(
            Registration("Test", "User", "user@example.com"),
            listOf(Organisation(orgCode, "Test org"), Organisation(anotherOrgCode, name = "Another org")),
        )
        coVerify(exactly = 1) { userService.createUser(any()) }
        coVerify(exactly = 1) { groupService.addUserToGroup(any(), deltaConfig.datamartDeltaReportUsers) }
        coVerify(exactly = 1) { groupService.addUserToGroup(any(), deltaConfig.datamartDeltaUser) }
        coVerify(exactly = 1) { groupService.addUserToGroup(any(), groupName(orgCode)) }
        coVerify(exactly = 1) { groupService.addUserToGroup(any(), groupName(anotherOrgCode)) }
        coVerify(exactly = 4) { groupService.addUserToGroup(any(), any()) }
        coVerify(exactly = 1) { setPasswordTokenService.createToken(any()) }
        assertTrue(registrationResult is RegistrationService.UserCreated)
    }

    @Test
    fun testStandardUserInRetiredAndNotRetiredOrg() = testSuspend {
        val registrationResult = registrationService.register(
            Registration("Test", "User", "user@example.com"),
            listOf(retiredOrganisation, Organisation(anotherOrgCode, name = "Another org")),
        )
        coVerify(exactly = 1) { userService.createUser(any()) }
        coVerify(exactly = 1) { groupService.addUserToGroup(any(), deltaConfig.datamartDeltaReportUsers) }
        coVerify(exactly = 1) { groupService.addUserToGroup(any(), deltaConfig.datamartDeltaUser) }
        coVerify(exactly = 0) { groupService.addUserToGroup(any(), groupName(orgCode)) }
        coVerify(exactly = 1) { groupService.addUserToGroup(any(), groupName(anotherOrgCode)) }
        coVerify(exactly = 3) { groupService.addUserToGroup(any(), any()) }
        coVerify(exactly = 1) { setPasswordTokenService.createToken(any()) }
        assertTrue(registrationResult is RegistrationService.UserCreated)
    }

    private fun groupName(orgCode: String) = String.format("%s-%s", deltaConfig.datamartDeltaUser, orgCode)
}
