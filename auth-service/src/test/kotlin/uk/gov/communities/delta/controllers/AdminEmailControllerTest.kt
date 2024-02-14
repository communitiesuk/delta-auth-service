package uk.gov.communities.delta.controllers

import io.ktor.client.*
import io.ktor.client.request.*
import io.ktor.http.*
import io.ktor.server.auth.*
import io.ktor.server.routing.*
import io.ktor.server.testing.*
import io.ktor.test.dispatcher.*
import io.mockk.*
import kotlinx.coroutines.runBlocking
import org.junit.*
import uk.gov.communities.delta.auth.bearerTokenRoutes
import uk.gov.communities.delta.auth.config.AzureADSSOClient
import uk.gov.communities.delta.auth.config.AzureADSSOConfig
import uk.gov.communities.delta.auth.config.DeltaConfig
import uk.gov.communities.delta.auth.config.LDAPConfig
import uk.gov.communities.delta.auth.controllers.internal.AdminEmailController
import uk.gov.communities.delta.auth.plugins.ApiError
import uk.gov.communities.delta.auth.plugins.configureSerialization
import uk.gov.communities.delta.auth.security.CLIENT_HEADER_AUTH_NAME
import uk.gov.communities.delta.auth.security.OAUTH_ACCESS_BEARER_TOKEN_AUTH_NAME
import uk.gov.communities.delta.auth.security.clientHeaderAuth
import uk.gov.communities.delta.auth.services.*
import uk.gov.communities.delta.helper.testLdapUser
import uk.gov.communities.delta.helper.testServiceClient
import java.time.Instant
import kotlin.test.assertEquals

class AdminEmailControllerTest {

    @Test
    fun testAdminSendActivationEmail() = testSuspend {
        testClient.post("/bearer/email/activation") {
            headers {
                append("Authorization", "Bearer ${adminSession.authToken}")
                append("Delta-Client", "${client.clientId}:${client.clientSecret}")
            }
            parameter("userEmail", disabledReceivingUserEmail)
        }.apply {
            assertEquals(HttpStatusCode.OK, status)
            coVerify(exactly = 1) { emailService.sendSetPasswordEmail(disabledReceivingUser, any(), adminSession, any()) }
            coVerify(exactly = 1) { setPasswordTokenService.createToken(disabledReceivingUser.cn) }
        }
    }

    @Test
    fun testReadOnlyAdminSendActivationEmail() = testSuspend {
        testClient.post("/bearer/email/activation") {
            headers {
                append("Authorization", "Bearer ${readOnlyAdminSession.authToken}")
                append("Delta-Client", "${client.clientId}:${client.clientSecret}")
            }
            parameter("userEmail", disabledReceivingUserEmail)
        }.apply {
            assertEquals(HttpStatusCode.OK, status)
            coVerify(exactly = 1) { emailService.sendSetPasswordEmail(disabledReceivingUser, any(), readOnlyAdminSession, any()) }
            coVerify(exactly = 1) { setPasswordTokenService.createToken(disabledReceivingUser.cn) }
        }
    }

    @Test
    fun testAdminSendActivationEmailEnabledUser() = testSuspend {
        Assert.assertThrows(ApiError::class.java) {
            runBlocking {
                testClient.post("/bearer/email/activation") {
                    headers {
                        append("Authorization", "Bearer ${adminSession.authToken}")
                        append("Delta-Client", "${client.clientId}:${client.clientSecret}")
                    }
                    parameter("userEmail", enabledReceivingUserEmail)
                }
            }
        }.apply {
            assertEquals("already_enabled", errorCode)
        }
        coVerify(exactly = 0) { emailService.sendSetPasswordEmail(any(), any(), any(), any()) }
        coVerify(exactly = 0) { setPasswordTokenService.createToken(any()) }
    }

    @Test
    fun testAdminSendActivationEmailAsNotAdmin() = testSuspend {
        Assert.assertThrows(ApiError::class.java) {
            runBlocking {
                testClient.post("/bearer/email/activation") {
                    headers {
                        append("Authorization", "Bearer ${userSession.authToken}")
                        append("Delta-Client", "${client.clientId}:${client.clientSecret}")
                    }
                    parameter("userEmail", disabledReceivingUserEmail)
                }
            }
        }.apply {
            assertEquals("forbidden", errorCode)
        }
        coVerify(exactly = 0) { emailService.sendSetPasswordEmail(any(), any(), any(), any()) }
        coVerify(exactly = 0) { setPasswordTokenService.createToken(any()) }
    }

    @Test
    fun testAdminSendActivationEmailSSOUser() = testSuspend {
        Assert.assertThrows(ApiError::class.java) {
            runBlocking {
                testClient.post("/bearer/email/activation") {
                    headers {
                        append("Authorization", "Bearer ${adminSession.authToken}")
                        append("Delta-Client", "${client.clientId}:${client.clientSecret}")
                    }
                    parameter("userEmail", disabledReceivingSSOUserEmail)
                }
            }
        }.apply {
            assertEquals("no_emails_to_sso_users", errorCode)
        }
        coVerify(exactly = 0) { emailService.sendSetPasswordEmail(any(), any(), any(), any()) }
        coVerify(exactly = 0) { setPasswordTokenService.createToken(any()) }
    }

    @Test
    fun testAdminSendResetPasswordEmail() = testSuspend {
        testClient.post("/bearer/email/reset-password") {
            headers {
                append("Authorization", "Bearer ${adminSession.authToken}")
                append("Delta-Client", "${client.clientId}:${client.clientSecret}")
            }
            parameter("userEmail", enabledReceivingUserEmail)
        }.apply {
            assertEquals(HttpStatusCode.OK, status)
            coVerify(exactly = 1) { emailService.sendResetPasswordEmail(enabledReceivingUser, "token", adminSession, any()) }
            coVerify(exactly = 1) { resetPasswordTokenService.createToken(any()) }
        }
    }

    @Test
    fun testReadOnlyAdminSendResetPasswordEmail() = testSuspend {
        testClient.post("/bearer/email/reset-password") {
            headers {
                append("Authorization", "Bearer ${readOnlyAdminSession.authToken}")
                append("Delta-Client", "${client.clientId}:${client.clientSecret}")
            }
            parameter("userEmail", enabledReceivingUserEmail)
        }.apply {
            assertEquals(HttpStatusCode.OK, status)
            coVerify(exactly = 1) { emailService.sendResetPasswordEmail(enabledReceivingUser, "token", readOnlyAdminSession, any()) }
            coVerify(exactly = 1) { resetPasswordTokenService.createToken(any()) }
        }
    }

    @Test
    fun testAdminSendResetPasswordEmailDisabledUser() = testSuspend {
        Assert.assertThrows(ApiError::class.java) {
            runBlocking {
                testClient.post("/bearer/email/reset-password") {
                    headers {
                        append("Authorization", "Bearer ${adminSession.authToken}")
                        append("Delta-Client", "${client.clientId}:${client.clientSecret}")
                    }
                    parameter("userEmail", disabledReceivingUserEmail)
                }
            }
        }.apply {
            assertEquals("not_enabled", errorCode)
        }
        coVerify(exactly = 0) { emailService.sendResetPasswordEmail(any(), any(), any(), any()) }
        coVerify(exactly = 0) { resetPasswordTokenService.createToken(any()) }
    }

    @Test
    fun testAdminSendResetPasswordEmailNotAdmin() = testSuspend {
        Assert.assertThrows(ApiError::class.java) {
            runBlocking {
                testClient.post("/bearer/email/reset-password") {
                    headers {
                        append("Authorization", "Bearer ${userSession.authToken}")
                        append("Delta-Client", "${client.clientId}:${client.clientSecret}")
                    }
                    parameter("userEmail", enabledReceivingUserEmail)
                }
            }
        }.apply {
            assertEquals("forbidden", errorCode)
        }
        coVerify(exactly = 0) { emailService.sendResetPasswordEmail(any(), any(), any(), any()) }
        coVerify(exactly = 0) { resetPasswordTokenService.createToken(any()) }
    }

    @Test
    fun testAdminSendResetPasswordEmailSSOUser() = testSuspend {
        Assert.assertThrows(ApiError::class.java) {
            runBlocking {
                testClient.post("/bearer/email/reset-password") {
                    headers {
                        append("Authorization", "Bearer ${adminSession.authToken}")
                        append("Delta-Client", "${client.clientId}:${client.clientSecret}")
                    }
                    parameter("userEmail", enabledReceivingSSOUserEmail)
                }
            }
        }.apply {
            assertEquals("no_emails_to_sso_users", errorCode)
        }
        coVerify(exactly = 0) { emailService.sendResetPasswordEmail(any(), any(), any(), any()) }
        coVerify(exactly = 0) { resetPasswordTokenService.createToken(any()) }
    }

    @Before
    fun resetMocks() {
        clearAllMocks()
        coEvery { oauthSessionService.retrieveFomAuthToken(any(), client) } answers { null }
        coEvery {
            oauthSessionService.retrieveFomAuthToken(
                adminSession.authToken,
                client
            )
        } answers { adminSession }
        coEvery { oauthSessionService.retrieveFomAuthToken(userSession.authToken, client) } answers { userSession }
        coEvery {
            oauthSessionService.retrieveFomAuthToken(
                readOnlyAdminSession.authToken,
                client
            )
        } answers { readOnlyAdminSession }
        coEvery { userLookupService.lookupUserByCn(adminUser.cn) } returns adminUser
        coEvery { userLookupService.lookupUserByCn(regularUser.cn) } returns regularUser
        coEvery { userLookupService.lookupUserByCn(readOnlyAdminUser.cn) } returns readOnlyAdminUser
        coEvery { userLookupService.lookupUserByCn(enabledReceivingUser.cn) } returns enabledReceivingUser
        coEvery { userLookupService.lookupUserByCn(enabledReceivingSSOUser.cn) } returns enabledReceivingSSOUser
        coEvery { userLookupService.lookupUserByCn(disabledReceivingUser.cn) } returns disabledReceivingUser
        coEvery { userLookupService.lookupUserByCn(disabledReceivingSSOUser.cn) } returns disabledReceivingSSOUser
        coEvery { resetPasswordTokenService.createToken(any()) } returns "token"
        coEvery { setPasswordTokenService.createToken(any()) } returns "token"
        coEvery { emailService.sendSetPasswordEmail(disabledReceivingUser, "token", adminSession, any()) } just runs
        coEvery { emailService.sendResetPasswordEmail(enabledReceivingUser, "token", adminSession, any()) } just runs
        coEvery { emailService.sendSetPasswordEmail(disabledReceivingUser, "token", readOnlyAdminSession, any()) } just runs
        coEvery { emailService.sendResetPasswordEmail(enabledReceivingUser, "token", readOnlyAdminSession, any()) } just runs
    }

    companion object {
        private lateinit var testApp: TestApplication
        private lateinit var testClient: HttpClient
        private lateinit var controller: AdminEmailController

        private val oauthSessionService = mockk<OAuthSessionService>()
        private val userLookupService = mockk<UserLookupService>()
        private val resetPasswordTokenService = mockk<ResetPasswordTokenService>()
        private val setPasswordTokenService = mockk<SetPasswordTokenService>()
        private val emailService = mockk<EmailService>()

        private val client = testServiceClient()
        private val adminUser = testLdapUser(cn = "admin", memberOfCNs = listOf(DeltaConfig.DATAMART_DELTA_ADMIN))
        private val readOnlyAdminUser =
            testLdapUser(cn = "read-only-admin", memberOfCNs = listOf(DeltaConfig.DATAMART_DELTA_READ_ONLY_ADMIN))
        private val regularUser = testLdapUser(cn = "user", memberOfCNs = emptyList())
        private const val enabledReceivingUserEmail = "enabled-receiving-user@test.com"
        private const val enabledReceivingSSOUserEmail = "enabled-receiving-user@sso.domain"
        private const val disabledReceivingUserEmail = "disabled-receiving-user@test.com"
        private const val disabledReceivingSSOUserEmail = "disabled-receiving-user@sso.domain"

        private val enabledReceivingUser = testLdapUser(
            email = enabledReceivingUserEmail,
            cn = LDAPConfig.emailToCN(enabledReceivingUserEmail),
            accountEnabled = true
        )
        private val enabledReceivingSSOUser = testLdapUser(
            email = enabledReceivingSSOUserEmail,
            cn = LDAPConfig.emailToCN(enabledReceivingSSOUserEmail),
            accountEnabled = true
        )
        private val disabledReceivingUser = testLdapUser(
            email = disabledReceivingUserEmail,
            cn = LDAPConfig.emailToCN(disabledReceivingUserEmail),
            accountEnabled = false
        )
        private val disabledReceivingSSOUser = testLdapUser(
            email = disabledReceivingSSOUserEmail,
            cn = LDAPConfig.emailToCN(disabledReceivingSSOUserEmail),
            accountEnabled = false
        )
        private val adminSession = OAuthSession(1, adminUser.cn, client, "adminAccessToken", Instant.now(), "trace")
        private val readOnlyAdminSession =
            OAuthSession(1, readOnlyAdminUser.cn, client, "readOnlyAdminAccessToken", Instant.now(), "trace")
        private val userSession = OAuthSession(1, regularUser.cn, client, "userAccessToken", Instant.now(), "trace")

        @BeforeClass
        @JvmStatic
        fun setup() {
            controller = AdminEmailController(
                AzureADSSOConfig(listOf(AzureADSSOClient("dev", "", "", "", "@sso.domain", required = true))),
                emailService,
                userLookupService,
                setPasswordTokenService,
                resetPasswordTokenService,
            )

            testApp = TestApplication {
                application {
                    configureSerialization()
                    authentication {
                        bearer(OAUTH_ACCESS_BEARER_TOKEN_AUTH_NAME) {
                            realm = "auth-service"
                            authenticate { oauthSessionService.retrieveFomAuthToken(it.token, client) }
                        }
                        clientHeaderAuth(CLIENT_HEADER_AUTH_NAME) {
                            headerName = "Delta-Client"
                            clients = listOf(testServiceClient())
                        }
                    }
                    routing {
                        bearerTokenRoutes(
                            mockk(relaxed = true),
                            controller,
                            mockk(relaxed = true),
                            mockk(relaxed = true),
                            mockk(relaxed = true),
                        )
                    }
                }
            }

            testClient = testApp.createClient {
                followRedirects = false
            }
        }

        @AfterClass
        @JvmStatic
        fun tearDown() {
            testApp.stop()
        }
    }

}