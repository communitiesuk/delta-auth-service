package uk.gov.communities.delta.controllers

import io.ktor.client.*
import io.ktor.client.plugins.*
import io.ktor.client.request.*
import io.ktor.client.request.forms.*
import io.ktor.client.statement.*
import io.ktor.http.*
import io.ktor.server.routing.*
import io.ktor.server.testing.*
import io.ktor.test.dispatcher.*
import io.mockk.*
import org.junit.AfterClass
import org.junit.Before
import org.junit.BeforeClass
import org.junit.Test
import uk.gov.communities.delta.auth.config.*
import uk.gov.communities.delta.auth.controllers.external.DeltaUserRegistrationController
import uk.gov.communities.delta.auth.plugins.configureTemplating
import uk.gov.communities.delta.auth.services.*
import uk.gov.communities.delta.helper.testLdapUser
import uk.gov.communities.delta.helper.testServiceClient
import kotlin.test.assertContains
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class DeltaUserRegistrationControllerTest {

    @Test
    fun testRegisterPage() = testSuspend {
        testClient.get("/register").apply {
            assertFormPage(bodyAsText(), status)
        }
    }

    @Test
    fun testRegisterPageFromSSO() = testSuspend {
        testClient.get("/register?fromSSOEmail=${"user@example.com".encodeURLParameter()}").apply {
            assertFormPage(bodyAsText(), status)
            assertTrue(bodyAsText().contains("No Delta account found with email user@example.com"))
        }
    }

    @Test
    fun testRegisterSuccessPage() = testSuspend {
        testClient.get("/register/success?emailAddress=" + (emailStart + standardDomain).encodeURLParameter()).apply {
            assertEquals(HttpStatusCode.OK, status)
            assertSuccessPage(bodyAsText())
        }
    }

    @Test
    fun testRegistrationForNewStandardUser() = testSuspend {
        val user = testLdapUser(email = emailStart + standardDomain, cn = cnStart + standardDomain)
        coEvery { userLookupService.userIfExists(emailStart + standardDomain) } returns null
        coEvery { userService.createUser(any(), any(), any(), any()) } returns user
        testClient.submitForm(
            url = "/register",
            formParameters = correctFormParameters(emailStart + standardDomain)
        ).apply {
            coVerify(exactly = 1) { userService.createUser(any(), null, null, any()) }
            coVerify(exactly = 1) {
                groupService.addUserToGroup(
                    any(), DeltaConfig.DATAMART_DELTA_REPORT_USERS, any(), null, userLookupService
                )
            }
            coVerify(exactly = 1) {
                groupService.addUserToGroup(any(), DeltaConfig.DATAMART_DELTA_USER, any(), null, userLookupService)
            }
            coVerify(exactly = 1) {
                groupService.addUserToGroup(any(), groupName(orgCode), any(), null, userLookupService)
            }
            assertSuccessPageRedirect(status, headers, emailStart + standardDomain)
            coVerify(exactly = 1) {
                emailService.sendSetPasswordEmail(
                    "Test",
                    "token",
                    cnStart + standardDomain,
                    user.getUUID(),
                    null,
                    userLookupService,
                    any(),
                    any()
                )
            }
        }
    }

    @Test
    fun testRegistrationFormValidationError() = testSuspend {
        // Testing stays on same page if there are validation errors - testing with different email addresses
        testClient.submitForm(
            url = "/register",
            formParameters = parameters {
                append("firstName", "Test")
                append("lastName", "Name")
                append("emailAddress", "user@example.com")
                append("confirmEmailAddress", "differentUser@example.com")
            }
        ).apply {
            coVerify(exactly = 0) { userService.createUser(any(), any(), any(), any()) }
            assertFormPage(bodyAsText(), status)
            assertContains(bodyAsText(), "Email addresses do not match")
        }
    }

    @Test
    fun testRegistrationFormValidationDomainError() = testSuspend {
        coEvery { organisationService.findAllByDomain(any()) } returns listOf()
        testClient.submitForm(
            url = "/register",
            formParameters = correctFormParameters(emailStart + standardDomain)
        ).apply {
            coVerify(exactly = 0) { userService.createUser(any(), any(), any(), any()) }
            assertFormPage(bodyAsText(), status)
            assertContains(bodyAsText(), "Email address domain not recognised")
        }
    }

    @Test
    fun testRegistrationFormValidationBadEmailError() = testSuspend {
        coEvery { organisationService.findAllByDomain(any()) } returns listOf()
        testClient.submitForm(
            url = "/register",
            formParameters = correctFormParameters("notAn@EmailStringcom")
        ).apply {
            coVerify(exactly = 0) { userService.createUser(any(), any(), any(), any()) }
            assertFormPage(bodyAsText(), status)
            assertContains(bodyAsText(), "Email address must be a valid email address")
        }
    }

    @Test
    fun testRegistrationForAlreadyExistingStandardUser() = testSuspend {
        val user = testLdapUser(email = emailStart + standardDomain)
        coEvery { userLookupService.userIfExists(emailStart + standardDomain) } returns user
        testClient.submitForm(
            url = "/register",
            formParameters = correctFormParameters(emailStart + standardDomain)
        ).apply {
            coVerify(exactly = 0) { userService.createUser(any(), any(), any(), any()) }
            assertSuccessPageRedirect(status, headers, emailStart + standardDomain)
            coVerify(exactly = 1) { emailService.sendAlreadyAUserEmail(any(), any(), any()) }
        }
    }

    @Test
    fun testRedirectOfNewRequiredSSOUser() = testSuspend {
        coEvery { userLookupService.userIfExists(emailStart + requiredDomain) } returns null
        testClient.submitForm(
            url = "/register",
            formParameters = correctFormParameters(emailStart + requiredDomain)
        ).apply {
            assertRedirectsToDelta(status, headers, emailStart + requiredDomain)
        }
    }

    @Test
    fun testRedirectOfExistingRequiredSSOUser() = testSuspend {
        coEvery {
            userLookupService.userIfExists(emailStart + requiredDomain)
        } returns testLdapUser(email = emailStart + requiredDomain)
        testClient.submitForm(
            url = "/register",
            formParameters = correctFormParameters(emailStart + requiredDomain)
        ).apply {
            assertRedirectsToDelta(status, headers, emailStart + requiredDomain)
        }
    }

    @Test
    fun testRegistrationOfNewNotRequiredSSOUser() = testSuspend {
        coEvery { userLookupService.userIfExists(emailStart + notRequiredDomain) } returns null
        val user = testLdapUser(email = emailStart + notRequiredDomain, cn = cnStart + notRequiredDomain)
        coEvery { userService.createUser(any(), any(), any(), any()) } returns user
        testClient.submitForm(
            url = "/register",
            formParameters = correctFormParameters(emailStart + notRequiredDomain)
        ).apply {
            coVerify(exactly = 1) { userService.createUser(any(), null, null, any()) }
            coVerify(exactly = 1) {
                groupService.addUserToGroup(
                    any(), DeltaConfig.DATAMART_DELTA_REPORT_USERS, any(), null, userLookupService
                )
            }
            coVerify(exactly = 1) {
                groupService.addUserToGroup(any(), DeltaConfig.DATAMART_DELTA_USER, any(), null, userLookupService)
            }
            coVerify(exactly = 1) {
                groupService.addUserToGroup(any(), groupName(orgCode), any(), null, userLookupService)
            }
            assertSuccessPageRedirect(status, headers, emailStart + notRequiredDomain)
            coVerify(exactly = 1) {
                emailService.sendSetPasswordEmail(
                    "Test",
                    "token",
                    cnStart + notRequiredDomain,
                    user.getUUID(),
                    null,
                    userLookupService,
                    any(),
                    any()
                )
            }
        }
    }

    @Test
    fun testRegistrationOfExistingNotRequiredSSOUser() = testSuspend {
        val user = testLdapUser(email = emailStart + notRequiredDomain, cn = cnStart + notRequiredDomain)
        coEvery { userLookupService.userIfExists(emailStart + notRequiredDomain) } returns user
        testClient.submitForm(
            url = "/register",
            formParameters = correctFormParameters(emailStart + notRequiredDomain)
        ).apply {
            coVerify(exactly = 0) { userService.createUser(any(), any(), any(), any()) }
            assertSuccessPageRedirect(status, headers, emailStart + notRequiredDomain)
            coVerify(exactly = 1) { emailService.sendAlreadyAUserEmail("Test", cnStart + notRequiredDomain, any()) }
        }
    }

    @Test
    fun testRegistrationOfStandardUserInRetiredOrg() = testSuspend {
        coEvery { organisationService.findAllByDomain(any()) } returns listOf(
            Organisation(orgCode, "Test org", "2023-09-30Z")
        )
        testClient.submitForm(
            url = "/register",
            formParameters = correctFormParameters(emailStart + notRequiredDomain)
        ).apply {
            coVerify(exactly = 0) { userService.createUser(any(), any(), any(), any()) }
            coVerify(exactly = 0) { emailService.sendSetPasswordEmail(any(), any(), any(), any(), any()) }
            assertFormPage(bodyAsText(), status)
            assertContains(bodyAsText(), "Email address domain not recognised")
        }
    }

    private fun assertSuccessPageRedirect(status: HttpStatusCode, headers: Headers, userEmail: String) {
        assertEquals(HttpStatusCode.Found, status)
        assertTrue("Should redirect to success page") { headers["Location"]!!.contains("/delta/register/success") }
        assertTrue("Should have email parameter") {
            headers["Location"]!!.contains("emailAddress=${userEmail.encodeURLParameter()}")
        }
    }

    private fun assertSuccessPage(bodyAsText: String) {
        assertContains(bodyAsText, "Your registration is pending your email activation")
    }

    private fun assertFormPage(bodyAsText: String, status: HttpStatusCode) {
        assertEquals(HttpStatusCode.OK, status)
        assertContains(bodyAsText, "Enter your details in the form below to request a new user account for Delta")
    }

    private fun assertRedirectsToDelta(status: HttpStatusCode, headers: Headers, emailAddress: String) {
        assertEquals(HttpStatusCode.Found, status)
        assertTrue("Should redirect to delta") {
            headers["Location"]!!.startsWith(deltaConfig.deltaWebsiteUrl + "/oauth2/authorization/delta-auth")
        }
        assertContains(
            headers["Location"]!!,
            "sso-client=required-client&expected-email=" + emailAddress.encodeURLParameter()
        )
    }

    private fun correctFormParameters(userEmail: String) = parameters {
        append("firstName", "Test")
        append("lastName", "Name")
        append("emailAddress", userEmail)
        append("confirmEmailAddress", userEmail)
    }

    private fun groupName(orgCode: String) = String.format("%s-%s", DeltaConfig.DATAMART_DELTA_USER, orgCode)

    @Before
    fun resetMocks() {
        clearAllMocks()
        coEvery { organisationService.findAllByDomain(any()) } returns listOf(Organisation(orgCode, "Test org"))
        coEvery { groupService.addUserToGroup(any(), any(), any(), null, userLookupService) } just runs
        coEvery { setPasswordTokenService.createToken(any(), any()) } returns "token"
        coEvery { emailService.sendAlreadyAUserEmail(any(), any(), any()) } just runs
        coEvery {
            emailService.sendSetPasswordEmail(any(), any(), any(), any(), null, userLookupService, any(), any())
        } just runs
    }

    companion object {
        val client = testServiceClient()
        private lateinit var testApp: TestApplication
        private lateinit var testClient: HttpClient
        private val deltaConfig = DeltaConfig.fromEnv()
        private val organisationService = mockk<OrganisationService>()
        private val setPasswordTokenService = mockk<SetPasswordTokenService>()
        private val emailService = mockk<EmailService>()
        private val authServiceConfig = AuthServiceConfig("http://localhost", null)
        private val userService = mockk<UserService>()
        private val userLookupService = mockk<UserLookupService>()
        private val groupService = mockk<GroupService>()
        private val userAuditService = mockk<UserAuditService>()
        const val emailStart = "user@"
        const val cnStart = "user!"
        const val standardDomain = "not.sso.domain.uk"
        const val requiredDomain = "sso.domain.uk"
        const val notRequiredDomain = "not.required.sso.domain.uk"
        const val orgCode = "E12345"

        @BeforeClass
        @JvmStatic
        fun setup() {
            val registrationService = RegistrationService(
                deltaConfig,
                EmailConfig.fromEnv(),
                LDAPConfig("testInvalidUrl", "", "", "", "", "", "", "", ""),
                setPasswordTokenService,
                emailService,
                userService,
                userLookupService,
                groupService
            )
            val controller = DeltaUserRegistrationController(
                deltaConfig,
                AzureADSSOConfig(
                    listOf(
                        AzureADSSOClient("required-client", "", "", "", "@sso.domain.uk", required = true),
                        AzureADSSOClient(
                            "not-required-client",
                            "",
                            "",
                            "",
                            "@not.required.sso.domain.uk",
                            required = false
                        )
                    )
                ),
                organisationService,
                registrationService,
                userAuditService,
            )
            testApp = TestApplication {
                application {
                    configureTemplating(false)
                    routing {
                        route("/register/success") {
                            controller.registerSuccessRoute(this)
                        }
                        route("/register") {
                            controller.registerFormRoutes(this)
                        }
                    }
                }
            }
            testClient = testApp.createClient {
                followRedirects = false
                defaultRequest {
                    headers.append("Origin", "http://localhost")
                }
            }
        }

        @AfterClass
        @JvmStatic
        fun tearDown() {
            testApp.stop()
        }
    }
}
