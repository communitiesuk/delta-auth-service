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
import uk.gov.communities.delta.auth.config.AzureADSSOClient
import uk.gov.communities.delta.auth.config.AzureADSSOConfig
import uk.gov.communities.delta.auth.config.DeltaConfig
import uk.gov.communities.delta.auth.controllers.external.DeltaForgotPasswordController
import uk.gov.communities.delta.auth.plugins.NoUserException
import uk.gov.communities.delta.auth.plugins.configureTemplating
import uk.gov.communities.delta.auth.services.*
import uk.gov.communities.delta.helper.testLdapUser
import uk.gov.communities.delta.helper.testServiceClient
import java.util.*
import kotlin.test.assertContains
import kotlin.test.assertEquals
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
        val user = testLdapUser(cn = userCN, email = userEmail)
        coEvery { userGUIDMapService.getGUIDFromEmail(user.email!!) } returns user.getGUID()
        coEvery { userLookupService.lookupUserByGUID(user.getGUID()) } returns user
        testClient.submitForm(
            url = "/forgot-password",
            formParameters = parameters { append("emailAddress", userEmail) }
        ).apply {
            coVerify(exactly = 1) { emailService.sendResetPasswordEmail(user, any(), null, any()) }
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
            assertEquals(HttpStatusCode.OK, status)
            assertFormPage(bodyAsText())
            assertContains(bodyAsText(), "Must be a valid email address")
        }
    }

    @Test
    fun testPostForgotPasswordPageNotSetPassword() = testSuspend {
        val user = testLdapUser(
            cn = userCN, email = userEmail, accountEnabled = false, javaUUIDObjectGuid = userGUID.toString()
        )
        coEvery { userGUIDMapService.getGUIDFromEmail(user.email!!) } returns user.getGUID()
        coEvery { userLookupService.lookupUserByGUID(user.getGUID()) } returns user
        coEvery { setPasswordTokenService.passwordNeverSetForUserCN(userGUID) } returns true
        coEvery { setPasswordTokenService.createToken(userGUID) } returns "setPasswordToken"
        testClient.submitForm(
            url = "/forgot-password",
            formParameters = parameters { append("emailAddress", userEmail) }
        ).apply {
            coVerify(exactly = 1) { emailService.sendPasswordNeverSetEmail(any(), any(), any()) }
            assertEquals(HttpStatusCode.Found, status)
            coVerify(exactly = 1) { setPasswordTokenService.createToken(userGUID) }
            coVerify(exactly = 0) { resetPasswordTokenService.createToken(userGUID) }
            assertTrue("Should redirect to email sent page") { headers["Location"]!!.contains("/delta/forgot-password/email-sent") }
        }
    }

    @Test
    fun testPostForgotPasswordPageNoUser() = testSuspend {
        coEvery { userGUIDMapService.getGUIDFromEmail(userEmail) } throws NoUserException("Test exception")
        testClient.submitForm(
            url = "/forgot-password",
            formParameters = parameters { append("emailAddress", userEmail) }
        ).apply {
            coVerify(exactly = 1) { emailService.sendNoUserEmail(userEmail) }
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
        assertContains(bodyAsText, "Your password reset link has been emailed to you")
        assertContains(bodyAsText, "mailto:$userEmail")
    }

    @Before
    fun resetMocks() {
        clearAllMocks()
        coEvery { resetPasswordTokenService.createToken(any()) } returns "token"
        coEvery { emailService.sendNoUserEmail(any()) } just runs
        coEvery { emailService.sendResetPasswordEmail(any(), any(), null, any()) } just runs
        coEvery { emailService.sendPasswordNeverSetEmail(any(), any(), any()) } just runs
    }

    companion object {
        val client = testServiceClient()
        private lateinit var testApp: TestApplication
        private lateinit var testClient: HttpClient
        private val userGUID = UUID.randomUUID()
        private const val userCN = "user!example.com"
        private const val userEmail = "user@example.com"
        private val deltaConfig = DeltaConfig.fromEnv()
        private val resetPasswordTokenService = mockk<ResetPasswordTokenService>()
        private val setPasswordTokenService = mockk<SetPasswordTokenService>()
        private val emailService = mockk<EmailService>()
        private val userLookupService = mockk<UserLookupService>()
        private val userGUIDMapService = mockk<UserGUIDMapService>()

        @BeforeClass
        @JvmStatic
        fun setup() {
            val controller = DeltaForgotPasswordController(
                deltaConfig,
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
                resetPasswordTokenService,
                setPasswordTokenService,
                userLookupService,
                userGUIDMapService,
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
