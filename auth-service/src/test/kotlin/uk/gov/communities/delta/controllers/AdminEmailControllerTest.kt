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
import uk.gov.communities.delta.auth.config.AzureADSSOClient
import uk.gov.communities.delta.auth.config.AzureADSSOConfig
import uk.gov.communities.delta.auth.config.LDAPConfig
import uk.gov.communities.delta.auth.controllers.internal.AdminEmailController
import uk.gov.communities.delta.auth.plugins.ApiError
import uk.gov.communities.delta.auth.plugins.configureSerialization
import uk.gov.communities.delta.auth.security.CLIENT_HEADER_AUTH_NAME
import uk.gov.communities.delta.auth.security.OAUTH_ACCESS_BEARER_TOKEN_AUTH_NAME
import uk.gov.communities.delta.auth.security.clientHeaderAuth
import uk.gov.communities.delta.auth.services.*
import uk.gov.communities.delta.auth.withBearerTokenAuth
import uk.gov.communities.delta.helper.testLdapUser
import uk.gov.communities.delta.helper.testServiceClient
import java.time.Instant
import kotlin.test.assertEquals

class AdminEmailControllerTest {

    @Test
    fun testAdminSendActivationEmail() = testSuspend {
        testClient.post("/email/activation") {
            headers {
                append("Authorization", "Bearer ${adminSession.authToken}")
                append("Delta-Client", "${client.clientId}:${client.clientSecret}")
            }
            parameter("userEmail", disabledReceivingUserEmail)
        }.apply {
            assertEquals(HttpStatusCode.OK, status)
            coVerify(exactly = 1) {
                emailService.sendSetPasswordEmail(disabledReceivingUser, any(), adminSession, userLookupService, any())
            }
            coVerify(exactly = 1) {
                setPasswordTokenService.createToken(disabledReceivingUser.cn, disabledReceivingUser.getUUID())
            }
        }
    }

    @Test
    fun testReadOnlyAdminSendActivationEmail() = testSuspend {
        testClient.post("/email/activation") {
            headers {
                append("Authorization", "Bearer ${readOnlyAdminSession.authToken}")
                append("Delta-Client", "${client.clientId}:${client.clientSecret}")
            }
            parameter("userEmail", disabledReceivingUserEmail)
        }.apply {
            assertEquals(HttpStatusCode.OK, status)
            coVerify(exactly = 1) {
                emailService.sendSetPasswordEmail(
                    disabledReceivingUser, any(), readOnlyAdminSession, userLookupService, any()
                )
            }
            coVerify(exactly = 1) {
                setPasswordTokenService.createToken(disabledReceivingUser.cn, disabledReceivingUser.getUUID())
            }
        }
    }

    @Test
    fun testAdminSendActivationEmailEnabledUser() = testSuspend {
        Assert.assertThrows(ApiError::class.java) {
            runBlocking {
                testClient.post("/email/activation") {
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
        coVerify(exactly = 0) { emailService.sendSetPasswordEmail(any(), any(), any(), any(), any()) }
        coVerify(exactly = 0) { setPasswordTokenService.createToken(any(), any()) }
    }

    @Test
    fun testAdminSendActivationEmailAsNotAdmin() = testSuspend {
        Assert.assertThrows(ApiError::class.java) {
            runBlocking {
                testClient.post("/email/activation") {
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
        coVerify(exactly = 0) { emailService.sendSetPasswordEmail(any(), any(), any(), any(), any()) }
        coVerify(exactly = 0) { setPasswordTokenService.createToken(any(), any()) }
    }

    @Test
    fun testAdminSendActivationEmailSSOUser() = testSuspend {
        Assert.assertThrows(ApiError::class.java) {
            runBlocking {
                testClient.post("/email/activation") {
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
        coVerify(exactly = 0) { emailService.sendSetPasswordEmail(any(), any(), any(), any(), any()) }
        coVerify(exactly = 0) { setPasswordTokenService.createToken(any(), any()) }
    }

    @Test
    fun testAdminSendResetPasswordEmail() = testSuspend {
        testClient.post("/email/reset-password") {
            headers {
                append("Authorization", "Bearer ${adminSession.authToken}")
                append("Delta-Client", "${client.clientId}:${client.clientSecret}")
            }
            parameter("userEmail", enabledReceivingUserEmail)
        }.apply {
            assertEquals(HttpStatusCode.OK, status)
            coVerify(exactly = 1) {
                emailService.sendResetPasswordEmail(
                    enabledReceivingUser, "token", adminSession, userLookupService, any()
                )
            }
            coVerify(exactly = 1) { resetPasswordTokenService.createToken(any(), any()) }
        }
    }

    @Test
    fun testReadOnlyAdminSendResetPasswordEmail() = testSuspend {
        testClient.post("/email/reset-password") {
            headers {
                append("Authorization", "Bearer ${readOnlyAdminSession.authToken}")
                append("Delta-Client", "${client.clientId}:${client.clientSecret}")
            }
            parameter("userEmail", enabledReceivingUserEmail)
        }.apply {
            assertEquals(HttpStatusCode.OK, status)
            coVerify(exactly = 1) {
                emailService.sendResetPasswordEmail(
                    enabledReceivingUser, "token", readOnlyAdminSession, userLookupService, any()
                )
            }
            coVerify(exactly = 1) { resetPasswordTokenService.createToken(any(), any()) }
        }
    }

    @Test
    fun testAdminSendResetPasswordEmailDisabledUser() = testSuspend {
        Assert.assertThrows(ApiError::class.java) {
            runBlocking {
                testClient.post("/email/reset-password") {
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
        coVerify(exactly = 0) { emailService.sendResetPasswordEmail(any(), any(), any(), any(), any()) }
        coVerify(exactly = 0) { resetPasswordTokenService.createToken(any(), any()) }
    }

    @Test
    fun testAdminSendResetPasswordEmailNotAdmin() = testSuspend {
        Assert.assertThrows(ApiError::class.java) {
            runBlocking {
                testClient.post("/email/reset-password") {
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
        coVerify(exactly = 0) { emailService.sendResetPasswordEmail(any(), any(), any(), any(), any()) }
        coVerify(exactly = 0) { resetPasswordTokenService.createToken(any(), any()) }
    }

    @Test
    fun testAdminSendResetPasswordEmailSSOUser() = testSuspend {
        Assert.assertThrows(ApiError::class.java) {
            runBlocking {
                testClient.post("/email/reset-password") {
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
        coVerify(exactly = 0) { emailService.sendResetPasswordEmail(any(), any(), any(), any(), any()) }
        coVerify(exactly = 0) { resetPasswordTokenService.createToken(any(), any()) }
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
        coEvery { userLookupService.lookupCurrentUser(adminSession) } returns adminUser
        coEvery { userLookupService.lookupCurrentUser(userSession) } returns regularUser
        coEvery { userLookupService.lookupCurrentUser(readOnlyAdminSession) } returns readOnlyAdminUser
        coEvery { userLookupService.lookupUserByEmail(enabledReceivingUser.email!!) } returns enabledReceivingUser
        coEvery { userLookupService.lookupUserByEmail(enabledReceivingSSOUser.email!!) } returns enabledReceivingSSOUser
        coEvery { userLookupService.lookupUserByEmail(disabledReceivingUser.email!!) } returns disabledReceivingUser
        coEvery { userLookupService.lookupUserByEmail(disabledReceivingSSOUser.email!!) } returns disabledReceivingSSOUser
        coEvery { resetPasswordTokenService.createToken(any(), any()) } returns "token"
        coEvery { setPasswordTokenService.createToken(any(), any()) } returns "token"
        coEvery {
            emailService.sendSetPasswordEmail(
                disabledReceivingUser, "token", adminSession, userLookupService, any()
            )
        } just runs
        coEvery {
            emailService.sendResetPasswordEmail(
                enabledReceivingUser, "token", adminSession, userLookupService, any()
            )
        } just runs
        coEvery {
            emailService.sendSetPasswordEmail(
                disabledReceivingUser, "token", readOnlyAdminSession, userLookupService, any()
            )
        } just runs
        coEvery {
            emailService.sendResetPasswordEmail(
                enabledReceivingUser, "token", readOnlyAdminSession, userLookupService, any()
            )
        } just runs
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
        private val adminUser = testLdapUser(cn = "admin", memberOfCNs = listOf(DeltaSystemRole.ADMIN.adCn()))
        private val readOnlyAdminUser =
            testLdapUser(cn = "read-only-admin", memberOfCNs = listOf(DeltaSystemRole.READ_ONLY_ADMIN.adCn()))
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
        private val adminSession = OAuthSession(
            1, adminUser.cn, adminUser.getUUID(), client, "adminAccessToken", Instant.now(), "trace", false
        )
        private val readOnlyAdminSession =
            OAuthSession(
                1,
                readOnlyAdminUser.cn,
                readOnlyAdminUser.getUUID(),
                client,
                "readOnlyAdminAccessToken",
                Instant.now(),
                "trace",
                false
            )
        private val userSession = OAuthSession(
            1, regularUser.cn, regularUser.getUUID(), client, "userAccessToken", Instant.now(), "trace", false
        )

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
                        withBearerTokenAuth {
                            route("/email") {
                                controller.route(this)
                            }
                        }
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
