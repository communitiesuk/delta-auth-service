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
import kotlinx.coroutines.runBlocking
import org.junit.*
import uk.gov.communities.delta.auth.config.DeltaConfig
import uk.gov.communities.delta.auth.controllers.external.DeltaResetPasswordController
import uk.gov.communities.delta.auth.plugins.UserVisibleServerError
import uk.gov.communities.delta.auth.plugins.configureTemplating
import uk.gov.communities.delta.auth.services.*
import uk.gov.communities.delta.helper.testLdapUser
import uk.gov.communities.delta.helper.testServiceClient
import kotlin.test.assertContains
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class DeltaResetPasswordControllerTest {


    @Test
    fun testResetPasswordPage() = testSuspend {
        testClient.get(
            "/reset-password?userGUID=" + user.getGUID().toString().encodeURLParameter() + "&token=$validToken"
        )
            .apply {
                assertEquals(HttpStatusCode.OK, status)
                assertFormPage(bodyAsText())
            }
    }

    @Test
    fun testResetPasswordPageWithCNParameter() = testSuspend {
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
        Assert.assertThrows(UserVisibleServerError::class.java) {
            runBlocking { testClient.get("/reset-password") }
        }.apply {
            assertEquals("reset_password_get_no_user_cn_or_guid", errorCode)
        }
    }

    @Test
    fun testGetResetPasswordPageExpiredToken() = testSuspend {
        testClient.get(
            "/reset-password?userGUID=" + user.getGUID().toString().encodeURLParameter() + "&token=expiredToken"
        )
            .apply {
                assertEquals(HttpStatusCode.OK, status)
                assertContains(bodyAsText(), "Your password reset link had expired.")
                assertFalse(bodyAsText().contains("Reset password"))
            }
    }

    @Test
    fun testResetPasswordSuccess() = testSuspend {
        testClient.submitForm(
            url = "/reset-password?userGUID=" + user.getGUID().toString().encodeURLParameter() + "&token=" + validToken,
            formParameters = correctFormParameters()
        ).apply {
            coVerify(exactly = 1) { resetPasswordTokenService.consumeTokenIfValid(validToken, user.getGUID()) }
            coVerify(exactly = 1) { userService.resetPassword(user.getGUID(), validPassword) }
            coVerify(exactly = 1) { userAuditService.resetPasswordAudit(user.getGUID(), any()) }
            assertSuccessPageRedirect(status, headers)
        }
    }

    @Test
    fun testResetPasswordValidationError() = testSuspend {
        testClient.submitForm(
            url = "/reset-password?userGUID=" + user.getGUID().toString().encodeURLParameter() + "&token=" + validToken,
            formParameters = parameters {
                append("newPassword", validPassword)
                append("confirmPassword", "Not$validPassword")
            }
        ).apply {
            coVerify(exactly = 0) { resetPasswordTokenService.consumeTokenIfValid(validToken, user.getGUID()) }
            coVerify(exactly = 0) { userService.resetPassword(any(), any()) }
            assertFormPage(bodyAsText())
            assertContains(bodyAsText(), "Passwords did not match")
        }
    }

    @Test
    fun testResetPasswordCommonPasswordError() = testSuspend {
        val badPassword = "qwerty123456"
        testClient.submitForm(
            url = "/reset-password?userGUID=" + user.getGUID().toString().encodeURLParameter() + "&token=" + validToken,
            formParameters = parameters {
                append("newPassword", badPassword)
                append("confirmPassword", badPassword)
            }
        ).apply {
            coVerify(exactly = 0) { resetPasswordTokenService.consumeTokenIfValid(validToken, user.getGUID()) }
            coVerify(exactly = 0) { userService.resetPassword(any(), any()) }
            assertFormPage(bodyAsText())
            assertContains(bodyAsText(), "Password must not be a commonly used password.")
        }
    }

    @Test
    fun testResetPasswordNameInPasswordError() = testSuspend {
        val badPassword = "userexample1"
        testClient.submitForm(
            url = "/reset-password?userGUID=" + user.getGUID().toString().encodeURLParameter() + "&token=" + validToken,
            formParameters = parameters {
                append("newPassword", badPassword)
                append("confirmPassword", badPassword)
            }
        ).apply {
            coVerify(exactly = 0) { resetPasswordTokenService.consumeTokenIfValid(validToken, user.getGUID()) }
            coVerify(exactly = 0) { userService.resetPassword(any(), any()) }
            assertFormPage(bodyAsText())
            assertContains(bodyAsText(), "Password must not contain any part(s) your username")
        }
    }

    @Test
    fun testPostResetPasswordExpiredToken() = testSuspend {
        testClient.submitForm(
            url = "/reset-password?userGUID=" + user.getGUID().toString()
                .encodeURLParameter() + "&token=" + expiredToken,
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
        testClient.submitForm(
            url = "/reset-password/expired",
            formParameters = parameters {
                append("userGUID", user.getGUID().toString())
                append("token", expiredToken)
            }
        ).apply {
            coVerify(exactly = 1) { resetPasswordTokenService.consumeTokenIfValid(expiredToken, user.getGUID()) }
            coVerify(exactly = 1) { emailService.sendResetPasswordEmail(any(), any(), null, any()) }
            coVerify(exactly = 1) { resetPasswordTokenService.createToken(user.getGUID()) }
            assertEquals(HttpStatusCode.OK, status)
            assertContains(bodyAsText(), "Your password reset link has been emailed to you")
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
            resetPasswordTokenService.validateToken(validToken, user.getGUID())
        } returns PasswordTokenService.ValidToken(validToken, user.getGUID())
        coEvery {
            resetPasswordTokenService.validateToken(expiredToken, user.getGUID())
        } returns PasswordTokenService.ExpiredToken(expiredToken, user.getGUID())
        coEvery {
            resetPasswordTokenService.validateToken(invalidToken, user.getGUID())
        } returns PasswordTokenService.NoSuchToken
        coEvery { resetPasswordTokenService.validateToken("", any()) } returns PasswordTokenService.NoSuchToken
        coEvery {
            resetPasswordTokenService.consumeTokenIfValid(validToken, user.getGUID())
        } returns PasswordTokenService.ValidToken(validToken, user.getGUID())
        coEvery {
            resetPasswordTokenService.consumeTokenIfValid(expiredToken, user.getGUID())
        } returns PasswordTokenService.ExpiredToken(expiredToken, user.getGUID())
        coEvery {
            resetPasswordTokenService.consumeTokenIfValid(invalidToken, user.getGUID())
        } returns PasswordTokenService.NoSuchToken
        coEvery { resetPasswordTokenService.consumeTokenIfValid("", any()) } returns PasswordTokenService.NoSuchToken
        coEvery { resetPasswordTokenService.createToken(user.getGUID()) } returns "token"
        coEvery { userService.resetPassword(user.getGUID(), validPassword) } just runs
        coEvery { emailService.sendResetPasswordEmail(any(), any(), null, any()) } just runs
        coEvery { userGUIDMapService.getGUID(user.cn) } returns user.getGUID()
        coEvery { userLookupService.lookupUserByGUID(user.getGUID()) } returns user
    }

    companion object {
        val client = testServiceClient()
        private lateinit var testApp: TestApplication
        private lateinit var testClient: HttpClient
        private const val validPassword = "RandomStringMoreThan12Characters"
        private const val validToken = "validToken"
        private const val invalidToken = "invalidToken"
        private const val expiredToken = "expiredToken"
        private const val deltaUserDnFormat = "CN=%s"
        val user = testLdapUser(
            cn = "user!example.com",
            dn = String.format(deltaUserDnFormat, "user!example.com"),
            email = "user@example.com"
        )
        private val deltaConfig = DeltaConfig.fromEnv()
        private val resetPasswordTokenService = mockk<ResetPasswordTokenService>()
        private val emailService = mockk<EmailService>()
        private val userService = mockk<UserService>()
        private val userLookupService = mockk<UserLookupService>()
        private val userGUIDMapService = mockk<UserGUIDMapService>()
        private var userAuditService = mockk<UserAuditService>(relaxed = true)


        @BeforeClass
        @JvmStatic
        fun setup() {
            val controller = DeltaResetPasswordController(
                deltaConfig,
                userService,
                resetPasswordTokenService,
                userLookupService,
                userGUIDMapService,
                emailService,
                userAuditService,
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
