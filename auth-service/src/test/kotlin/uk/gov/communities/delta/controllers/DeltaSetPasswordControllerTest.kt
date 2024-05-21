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
import uk.gov.communities.delta.auth.config.DeltaConfig
import uk.gov.communities.delta.auth.config.EmailConfig
import uk.gov.communities.delta.auth.config.LDAPConfig
import uk.gov.communities.delta.auth.controllers.external.DeltaSetPasswordController
import uk.gov.communities.delta.auth.plugins.UserVisibleServerError
import uk.gov.communities.delta.auth.plugins.configureTemplating
import uk.gov.communities.delta.auth.services.*
import uk.gov.communities.delta.helper.testLdapUser
import uk.gov.communities.delta.helper.testServiceClient
import java.util.*
import kotlin.test.assertContains
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class DeltaSetPasswordControllerTest {


    @Test
    fun testSetPasswordPage() = testSuspend {
        testClient.get("/set-password?userCN=user%21example.com&token=$validToken")
            .apply {
                assertEquals(HttpStatusCode.OK, status)
                assertFormPage(bodyAsText())
            }
    }

    @Test
    fun testSetPasswordSuccessPage() = testSuspend {
        testClient.get("/set-password/success")
            .apply {
                assertEquals(HttpStatusCode.OK, status)
                assertSuccessPage(bodyAsText())
            }
    }

    @Test
    fun testSetPasswordPageNoParametersThrowsError() = testSuspend {
        Assert.assertThrows(UserVisibleServerError::class.java) {
            runBlocking { testClient.get("/set-password") }
        }.apply {
            assertEquals("set_password_no_user_cn_or_guid", errorCode)
        }
    }

    @Test
    fun testGetSetPasswordPageExpiredTokenSendsEmail() = testSuspend {
        testClient.get("/set-password?userCN=user%21example.com&token=expiredToken")
            .apply {
                assertEquals(HttpStatusCode.OK, status)
                assertContains(bodyAsText(), "Your activation link had expired.")
                assertFalse(bodyAsText().contains("Set password"))
            }
    }

    @Test
    fun testSetPasswordSuccess() = testSuspend {
        testClient.submitForm(
            url = "/set-password?userCN=" + user.cn.encodeURLParameter() + "&token=" + validToken,
            formParameters = correctFormParameters()
        ).apply {
            coVerify(exactly = 1) { setPasswordTokenService.consumeTokenIfValid(validToken, user.cn, user.getGUID()) }
            coVerify(exactly = 1) { userAuditService.setPasswordAudit(user.cn, user.getGUID(), any()) }
            assertSuccessPageRedirect(status, headers)
        }
    }

    @Test
    fun testSetPasswordValidationError() = testSuspend {
        testClient.submitForm(
            url = "/set-password?userCN=" + user.cn.encodeURLParameter() + "&token=" + validToken,
            formParameters = parameters {
                append("newPassword", validPassword)
                append("confirmPassword", "Not$validPassword")
            }
        ).apply {
            coVerify(exactly = 0) { setPasswordTokenService.consumeTokenIfValid(validToken, user.cn, user.getGUID()) }
            assertFormPage(bodyAsText())
            assertContains(bodyAsText(), "Passwords did not match")
        }
    }

    @Test
    fun testSetPasswordCommonPasswordError() = testSuspend {
        val badPassword = "qwerty123456"
        testClient.submitForm(
            url = "/set-password?userCN=" + user.cn.encodeURLParameter() + "&token=" + validToken,
            formParameters = parameters {
                append("newPassword", badPassword)
                append("confirmPassword", badPassword)
            }
        ).apply {
            coVerify(exactly = 0) { setPasswordTokenService.consumeTokenIfValid(validToken, user.cn, user.getGUID()) }
            assertFormPage(bodyAsText())
            assertContains(
                bodyAsText(),
                "Password must not be a commonly used password."
            )
        }
    }

    @Test
    fun testSetPasswordNameInPasswordError() = testSuspend {
        val badPassword = "userexample1"
        testClient.submitForm(
            url = "/set-password?userCN=" + user.cn.encodeURLParameter() + "&token=" + validToken,
            formParameters = parameters {
                append("newPassword", badPassword)
                append("confirmPassword", badPassword)
            }
        ).apply {
            coVerify(exactly = 0) { setPasswordTokenService.consumeTokenIfValid(validToken, user.cn, user.getGUID()) }
            assertFormPage(bodyAsText())
            assertContains(
                bodyAsText(),
                "Password must not contain any part(s) your username"
            )
        }
    }

    @Test
    fun testPostSetPasswordExpiredToken() = testSuspend {
        testClient.submitForm(
            url = "/set-password?userCN=" + user.cn.encodeURLParameter() + "&token=" + expiredToken,
            formParameters = parameters {
                append("newPassword", validPassword)
                append("confirmPassword", validPassword)
            }
        ).apply {
            assertEquals(HttpStatusCode.OK, status)
            assertContains(bodyAsText(), "Your activation link had expired.")
            assertFalse(bodyAsText().contains("Set password"))
        }
    }

    @Test
    fun testPostResendActivationEmail() = testSuspend {
        coEvery { userLookupService.lookupUserByCn(user.cn) } returns testLdapUser()
        testClient.submitForm(
            url = "/set-password/expired",
            formParameters = parameters {
                append("userGUID", user.getGUID().toString())
                append("token", expiredToken)
            }
        ).apply {
            coVerify(exactly = 1) { setPasswordTokenService.consumeTokenIfValid(expiredToken, user.cn, user.getGUID()) }
            coVerify(exactly = 1) { emailService.sendNotYetEnabledEmail(any(), any(), any()) }
            coVerify(exactly = 1) { setPasswordTokenService.createToken(user.cn, user.getGUID()) }
            assertEquals(HttpStatusCode.OK, status)
            assertContains(bodyAsText(), "Your registration is pending your email activation")
        }
    }

    private fun assertSuccessPageRedirect(status: HttpStatusCode, headers: Headers) {
        assertEquals(HttpStatusCode.Found, status)
        assertTrue("Should redirect to success page") { headers["Location"]!!.contains("/delta/set-password/success") }
    }

    private fun assertSuccessPage(bodyAsText: String) {
        assertContains(bodyAsText, "Your password has been set and your registration is completed")
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
            setPasswordTokenService.validateToken(validToken, user.cn, user.getGUID())
        } returns PasswordTokenService.ValidToken(validToken, user.getGUID())
        coEvery {
            setPasswordTokenService.validateToken(expiredToken, user.cn, user.getGUID())
        } returns PasswordTokenService.ExpiredToken(expiredToken, user.getGUID())
        coEvery {
            setPasswordTokenService.validateToken(invalidToken, user.cn, user.getGUID())
        } returns PasswordTokenService.NoSuchToken
        coEvery {
            setPasswordTokenService.validateToken("", any(), any())
        } returns PasswordTokenService.NoSuchToken
        coEvery {
            setPasswordTokenService.consumeTokenIfValid(validToken, user.cn, user.getGUID())
        } returns PasswordTokenService.ValidToken(validToken, user.getGUID())
        coEvery {
            setPasswordTokenService.consumeTokenIfValid(expiredToken, user.cn, user.getGUID())
        } returns PasswordTokenService.ExpiredToken(expiredToken, user.getGUID())
        coEvery {
            setPasswordTokenService.consumeTokenIfValid(invalidToken, user.cn, user.getGUID())
        } returns PasswordTokenService.NoSuchToken
        coEvery {
            setPasswordTokenService.consumeTokenIfValid("", any(), any())
        } returns PasswordTokenService.NoSuchToken
        coEvery { setPasswordTokenService.createToken(user.cn, user.getGUID()) } returns "token"
        coEvery { userService.setPasswordAndEnable(user.dn, validPassword) } just runs
        coEvery { emailService.sendNotYetEnabledEmail(any(), any(), any()) } just runs
        coEvery { userLookupService.lookupUserByCn(user.cn) } returns user
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
        private val user = testLdapUser(
            cn = "user!example.com",
            dn = String.format(deltaUserDnFormat, "user!example.com"),
            email = "user@example.com"
        )
        private val deltaConfig = DeltaConfig.fromEnv()
        private val ldapConfig = LDAPConfig("testInvalidUrl", "", deltaUserDnFormat, "", "", "", "", "", "")
        private val authenticator: Authenticator = object : Authenticator() {
            override fun getPasswordAuthentication(): PasswordAuthentication {
                return PasswordAuthentication("", "")
            }
        }
        private val emailConfig = EmailConfig(Properties(), authenticator, "", "", "", "", false, emptyList())
        private val setPasswordTokenService = mockk<SetPasswordTokenService>()
        private val emailService = mockk<EmailService>()
        private val userService = mockk<UserService>()
        private val userLookupService = mockk<UserLookupService>()
        private val userAuditService = mockk<UserAuditService>(relaxed = true)


        @BeforeClass
        @JvmStatic
        fun setup() {
            val controller = DeltaSetPasswordController(
                deltaConfig,
                ldapConfig,
                userService,
                setPasswordTokenService,
                userLookupService,
                emailService,
                userAuditService,
            )
            testApp = TestApplication {
                application {
                    configureTemplating(false)
                    routing {
                        route("/set-password/success") {
                            controller.setPasswordSuccessRoute(this)
                        }
                        route("set-password/expired") {
                            controller.setPasswordExpired(this)
                        }
                        route("/set-password") {
                            controller.setPasswordFormRoutes(this)
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
