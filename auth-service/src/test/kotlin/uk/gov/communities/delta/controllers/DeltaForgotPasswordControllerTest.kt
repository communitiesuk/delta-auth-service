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
import jakarta.mail.Authenticator
import jakarta.mail.PasswordAuthentication
import org.junit.AfterClass
import org.junit.Before
import org.junit.BeforeClass
import org.junit.Test
import uk.gov.communities.delta.auth.config.*
import uk.gov.communities.delta.auth.controllers.external.DeltaForgotPasswordController
import uk.gov.communities.delta.auth.plugins.configureTemplating
import uk.gov.communities.delta.auth.services.EmailService
import uk.gov.communities.delta.auth.services.PasswordTokenService
import uk.gov.communities.delta.auth.services.UserLookupService
import uk.gov.communities.delta.helper.testLdapUser
import uk.gov.communities.delta.helper.testServiceClient
import java.util.*
import javax.naming.NameNotFoundException
import kotlin.test.assertContains
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class DeltaForgotPasswordControllerTest {

    @Test
    fun testGetForgotPasswordPage() = testSuspend {
        testClient.get("/forgot-password").apply {
            assertEquals(HttpStatusCode.OK, status)
            assertFormPage(bodyAsText())
        }
    }

    @Test
    fun testGetForgotPasswordEmailSentPage() = testSuspend {
        testClient.get("/forgot-password/email-sent?emailAddress=user%40example.com").apply {
            assertEquals(HttpStatusCode.OK, status)
            assertSentEmailPage(bodyAsText())
        }
    }

    @Test
    fun testPostForgotPasswordPage() = testSuspend {
        coEvery { userLookupService.lookupUserByCn(userCN) } returns testLdapUser()
        testClient.submitForm(
            url = "/forgot-password",
            formParameters = parameters { append("emailAddress", userEmail) }
        ).apply {
            assertEquals("reset-password", emailTemplate.captured)
            assertEquals(HttpStatusCode.Found, status)
            assertTrue("Should redirect to email sent page") { headers["Location"]!!.contains("/delta/forgot-password/email-sent") }
        }
    }

    @Test
    fun testPostForgotPasswordPageValidationError() = testSuspend {
        testClient.submitForm(
            url = "/forgot-password",
            formParameters = parameters { append("emailAddress", "this is not an email address") }
        ).apply {
            assertFalse(emailTemplate.isCaptured)
            assertEquals(HttpStatusCode.OK, status)
            assertFormPage(bodyAsText())
            assertContains(bodyAsText(), "Must be a valid email address")
        }
    }

    @Test
    fun testPostForgotPasswordPageNotSetPassword() = testSuspend {
        coEvery { userLookupService.lookupUserByCn(userCN) } returns testLdapUser(accountEnabled = false)
        coEvery { passwordTokenService.passwordNeverSetForUserCN(userCN) } returns true
        coEvery { passwordTokenService.createToken(userCN, true) } returns "setPasswordToken"
        testClient.submitForm(
            url = "/forgot-password",
            formParameters = parameters { append("emailAddress", userEmail) }
        ).apply {
            assertEquals("password-never-set", emailTemplate.captured)
            assertEquals(HttpStatusCode.Found, status)
            coVerify(exactly = 1) { passwordTokenService.createToken(userCN, true) }
            coVerify(exactly = 0) { passwordTokenService.createToken(userCN, false) }
            assertTrue("Should redirect to email sent page") { headers["Location"]!!.contains("/delta/forgot-password/email-sent") }
        }
    }

    @Test
    fun testPostForgotPasswordPageNoUser() = testSuspend {
        coEvery { userLookupService.lookupUserByCn(userCN) } throws NameNotFoundException("User does not exist")
        testClient.submitForm(
            url = "/forgot-password",
            formParameters = parameters { append("emailAddress", userEmail) }
        ).apply {
            assertEquals("no-user-account", emailTemplate.captured)
            assertEquals(HttpStatusCode.Found, status)
            assertTrue("Should redirect to email sent page") { headers["Location"]!!.contains("/delta/forgot-password/email-sent") }
        }
    }

    @Test
    fun testPostForgotPasswordPagesSSOUser() = testSuspend {
        testClient.submitForm(
            url = "/forgot-password",
            formParameters = parameters { append("emailAddress", "user@sso-example.com") }
        ).apply {
            assertFalse(emailTemplate.isCaptured)
            assertEquals(HttpStatusCode.Found, status)
            assertTrue("Should redirect to delta") { headers["Location"]!!.contains(deltaConfig.deltaWebsiteUrl + "/oauth2/authorization/delta-auth") }
            assertContains(headers["Location"]!!, "sso-client=ssoInternalIDTest")
            assertContains(headers["Location"]!!, "expected-email=user%40sso-example.com")
        }
    }

    private fun assertFormPage(bodyAsText: String) {
        assertContains(bodyAsText, "Forgot Password")
    }

    private fun assertSentEmailPage(bodyAsText: String) {
        assertContains(bodyAsText, "Your password reset link has been email to you")
        assertContains(bodyAsText, "mailto:$userEmail")
    }

    @Before
    fun resetMocks() {
        clearAllMocks()
        emailTemplate.clear()
        coEvery { passwordTokenService.createToken(any(), false) } returns "token"
        coEvery { emailService.sendTemplateEmail(capture(emailTemplate), any(), any(), any()) } just runs
    }

    companion object {
        val client = testServiceClient()
        private lateinit var testApp: TestApplication
        private lateinit var testClient: HttpClient
        private const val userCN = "user!example.com"
        private const val userEmail = "user@example.com"
        private val deltaConfig = DeltaConfig.fromEnv()
        private val authenticator: Authenticator = object : Authenticator() {
            override fun getPasswordAuthentication(): PasswordAuthentication {
                return PasswordAuthentication("", "")
            }
        }
        private val emailConfig = EmailConfig(Properties(), authenticator, "", "", "", "")
        private val authServiceConfig = AuthServiceConfig("http://localhost", null)
        private val passwordTokenService = mockk<PasswordTokenService>()
        private val emailService = mockk<EmailService>()
        private val userLookupService = mockk<UserLookupService>()
        private var emailTemplate = slot<String>()


        @BeforeClass
        @JvmStatic
        fun setup() {
            val controller = DeltaForgotPasswordController(
                deltaConfig,
                emailConfig,
                authServiceConfig,
                AzureADSSOConfig(
                    listOf(
                        AzureADSSOClient(
                            "ssoInternalIDTest",
                            "",
                            "",
                            "",
                            "@sso-example.com",
                            required = true
                        )
                    )
                ),
                passwordTokenService,
                userLookupService,
                emailService,
            )
            testApp = TestApplication {
                application {
                    configureTemplating(false)
                    routing {
                        route("/forgot-password/email-sent") {
                            controller.forgotPasswordEmailSentRoute(this)
                        }
                        route("/forgot-password") {
                            controller.forgotPasswordFormRoutes(this)
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