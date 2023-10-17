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
import kotlinx.coroutines.runBlocking
import org.junit.*
import uk.gov.communities.delta.auth.config.AuthServiceConfig
import uk.gov.communities.delta.auth.config.DeltaConfig
import uk.gov.communities.delta.auth.config.EmailConfig
import uk.gov.communities.delta.auth.config.LDAPConfig
import uk.gov.communities.delta.auth.controllers.external.DeltaResetPasswordController
import uk.gov.communities.delta.auth.controllers.external.ResetPasswordException
import uk.gov.communities.delta.auth.plugins.configureTemplating
import uk.gov.communities.delta.auth.services.*
import uk.gov.communities.delta.helper.testLdapUser
import uk.gov.communities.delta.helper.testServiceClient
import java.util.*
import kotlin.test.assertContains
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class DeltaResetPasswordControllerTest {


    @Test
    fun testResetPasswordPage() = testSuspend {
        testClient.get("/reset-password?userCN=user%21example.com&token=$validToken")
            .apply {
                assertEquals(HttpStatusCode.OK, status)
                assertFormPage(bodyAsText())
            }
    }

    @Test
    fun testResetPasswordSuccessPage() = testSuspend {
        testClient.get("/reset-password/success")
            .apply {
                assertEquals(HttpStatusCode.OK, status)
                assertSuccessPage(bodyAsText())
            }
    }


    @Test
    fun testResetPasswordPageNoParametersThrowsError() = testSuspend {
        Assert.assertThrows(ResetPasswordException::class.java) {
            runBlocking { testClient.get("/reset-password") }
        }.apply {
            assertEquals("reset_password_no_token", errorCode)
        }
    }

    @Test
    fun testGetResetPasswordPageExpiredToken() = testSuspend {
        coEvery { userLookupService.lookupUserByCn(userCN) } returns testLdapUser()
        testClient.get("/reset-password?userCN=user%21example.com&token=expiredToken")
            .apply {
                assertEquals(HttpStatusCode.OK, status)
                assertContains(bodyAsText(), "Your password reset link had expired.")
                assertFalse(bodyAsText().contains("Reset password"))
            }
    }

    @Test
    fun testResetPasswordSuccess() = testSuspend {
        testClient.submitForm(
            url = "/reset-password?userCN=" + userCN.encodeURLParameter() + "&token=" + validToken,
            formParameters = correctFormParameters()
        ).apply {
            coVerify(exactly = 1) { resetPasswordTokenService.consumeToken(validToken, userCN) }
            coVerify(exactly = 1) { userService.resetPassword(userDN, validPassword) }
            assertSuccessPageRedirect(status, headers)
        }
    }

    @Test
    fun testResetPasswordValidationError() = testSuspend {
        testClient.submitForm(
            url = "/reset-password?userCN=" + userCN.encodeURLParameter() + "&token=" + validToken,
            formParameters = parameters {
                append("newPassword", validPassword)
                append("confirmPassword", "Not$validPassword")
            }
        ).apply {
            coVerify(exactly = 0) { resetPasswordTokenService.consumeToken(validToken, userCN) }
            coVerify(exactly = 0) { userService.resetPassword(any(), any()) }
            assertFormPage(bodyAsText())
            assertContains(bodyAsText(), "Passwords did not match")
        }
    }

    @Test
    fun testResetPasswordCommonPasswordError() = testSuspend {
        val badPassword = "qwerty123456"
        testClient.submitForm(
            url = "/reset-password?userCN=" + userCN.encodeURLParameter() + "&token=" + validToken,
            formParameters = parameters {
                append("newPassword", badPassword)
                append("confirmPassword", badPassword)
            }
        ).apply {
            coVerify(exactly = 0) { resetPasswordTokenService.consumeToken(validToken, userCN) }
            coVerify(exactly = 0) { userService.resetPassword(any(), any()) }
            assertFormPage(bodyAsText())
            assertContains(bodyAsText(), "Password must not be a commonly used password.")
        }
    }

    @Test
    fun testResetPasswordNameInPasswordError() = testSuspend {
        val badPassword = "userexample1"
        testClient.submitForm(
            url = "/reset-password?userCN=" + userCN.encodeURLParameter() + "&token=" + validToken,
            formParameters = parameters {
                append("newPassword", badPassword)
                append("confirmPassword", badPassword)
            }
        ).apply {
            coVerify(exactly = 0) { resetPasswordTokenService.consumeToken(validToken, userCN) }
            coVerify(exactly = 0) { userService.resetPassword(any(), any()) }
            assertFormPage(bodyAsText())
            assertContains(bodyAsText(), "Password must not contain any part(s) your username")
        }
    }

    @Test
    fun testPostResetPasswordExpiredToken() = testSuspend {
        coEvery { userLookupService.lookupUserByCn(userCN) } returns testLdapUser()
        testClient.submitForm(
            url = "/reset-password?userCN=" + userCN.encodeURLParameter() + "&token=" + expiredToken,
            formParameters = parameters {
                append("newPassword", validPassword)
                append("confirmPassword", validPassword)
            }
        ).apply {
            assertEquals(HttpStatusCode.OK, status)
            assertContains(bodyAsText(), "Your password reset link had expired.")
            assertFalse(bodyAsText().contains("Reset password"))
            coVerify(exactly = 0) { userService.resetPassword(any(), any()) }
        }
    }

    @Test
    fun testPostResendResetPasswordEmail() = testSuspend {
        coEvery { userLookupService.lookupUserByCn(userCN) } returns testLdapUser()
        testClient.submitForm(
            url = "/reset-password/expired",
            formParameters = parameters {
                append("userCN", userCN)
                append("token", expiredToken)
            }
        ).apply {
            coVerify(exactly = 1) { resetPasswordTokenService.consumeToken(expiredToken, userCN) }
            assertEquals(emailTemplate.captured, "reset-password")
            coVerify(exactly = 1) { resetPasswordTokenService.createToken(userCN) }
            assertEquals(HttpStatusCode.OK, status)
            assertContains(bodyAsText(), "Your password reset link has been email to you")
        }
    }

    private fun assertSuccessPageRedirect(status: HttpStatusCode, headers: Headers) {
        assertEquals(HttpStatusCode.Found, status)
        assertTrue("Should redirect to success page") { headers["Location"]!!.contains("/delta/reset-password/success") }
    }

    private fun assertSuccessPage(bodyAsText: String) {
        assertContains(bodyAsText, "Your password has been reset")
    }

    private fun assertFormPage(bodyAsText: String) {
        assertContains(bodyAsText, "Set password")
    }

    private fun correctFormParameters() = parameters {
        append("newPassword", validPassword)
        append("confirmPassword", validPassword)
    }

    @Before
    fun resetMocks() {
        clearAllMocks()
        coEvery {
            resetPasswordTokenService.validateToken(validToken, userCN)
        } returns PasswordTokenService.ValidToken(validToken, userCN)
        coEvery {
            resetPasswordTokenService.validateToken(expiredToken, userCN)
        } returns PasswordTokenService.ExpiredToken(expiredToken, userCN)
        coEvery {
            resetPasswordTokenService.validateToken(invalidToken, userCN)
        } returns PasswordTokenService.NoSuchToken
        coEvery {
            resetPasswordTokenService.validateToken("", any())
        } returns PasswordTokenService.NoSuchToken
        coEvery {
            resetPasswordTokenService.consumeToken(validToken, userCN)
        } returns PasswordTokenService.ValidToken(validToken, userCN)
        coEvery {
            resetPasswordTokenService.consumeToken(expiredToken, userCN)
        } returns PasswordTokenService.ExpiredToken(expiredToken, userCN)
        coEvery {
            resetPasswordTokenService.consumeToken(invalidToken, userCN)
        } returns PasswordTokenService.NoSuchToken
        coEvery {
            resetPasswordTokenService.consumeToken("", any())
        } returns PasswordTokenService.NoSuchToken
        coEvery { emailService.sendTemplateEmail(capture(emailTemplate), any(), any(), any()) } just runs
        coEvery { resetPasswordTokenService.createToken(userCN) } returns "token"
        coEvery { userService.resetPassword(userDN, validPassword) } just runs
    }

    companion object {
        val client = testServiceClient()
        private lateinit var testApp: TestApplication
        private lateinit var testClient: HttpClient
        private const val validPassword = "RandomStringMoreThan12Characters"
        private const val validToken = "validToken"
        private const val invalidToken = "invalidToken"
        private const val expiredToken = "expiredToken"
        private const val userCN = "user!example.com"
        private const val deltaUserDnFormat = "CN=%s"
        private val userDN = String.format(deltaUserDnFormat, userCN)
        private val deltaConfig = DeltaConfig.fromEnv()
        private val ldapConfig = LDAPConfig("testInvalidUrl", "", deltaUserDnFormat, "", "", "", "", "", "")
        private val authenticator: Authenticator = object : Authenticator() {
            override fun getPasswordAuthentication(): PasswordAuthentication {
                return PasswordAuthentication("", "")
            }
        }
        private val emailConfig = EmailConfig(Properties(), authenticator, "", "", "", "")
        private val authServiceConfig = AuthServiceConfig("http://localhost", null)
        private val resetPasswordTokenService = mockk<ResetPasswordTokenService>()
        private val emailService = mockk<EmailService>()
        private val userService = mockk<UserService>()
        private val userLookupService = mockk<UserLookupService>()
        private var emailTemplate = slot<String>()


        @BeforeClass
        @JvmStatic
        fun setup() {
            val controller = DeltaResetPasswordController(
                deltaConfig,
                ldapConfig,
                emailConfig,
                authServiceConfig,
                userService,
                resetPasswordTokenService,
                userLookupService,
                emailService
            )
            testApp = TestApplication {
                application {
                    configureTemplating(false)
                    routing {
                        route("/reset-password/success") {
                            controller.resetPasswordSuccessRoute(this)
                        }
                        route("/reset-password/expired") {
                            controller.resetPasswordExpired(this)
                        }
                        route("/reset-password") {
                            controller.resetPasswordFormRoutes(this)
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
