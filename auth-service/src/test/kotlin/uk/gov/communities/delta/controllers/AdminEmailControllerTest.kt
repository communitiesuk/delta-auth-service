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
            parameter("userEmail", disabledReceivingUser.email)
        }.apply {
            assertEquals(HttpStatusCode.OK, status)
            coVerify(exactly = 1) {
                emailService.sendSetPasswordEmail(disabledReceivingUser, any(), adminSession, any())
            }
            coVerify(exactly = 1) {
                setPasswordTokenService.createToken(disabledReceivingUser.getGUID())
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
            parameter("userEmail", disabledReceivingUser.email)
        }.apply {
            assertEquals(HttpStatusCode.OK, status)
            coVerify(exactly = 1) {
                emailService.sendSetPasswordEmail(disabledReceivingUser, any(), readOnlyAdminSession, any())
            }
            coVerify(exactly = 1) { setPasswordTokenService.createToken(disabledReceivingUser.getGUID()) }
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
                    parameter("userEmail", enabledReceivingUser.email)
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
                testClient.post("/email/activation") {
                    headers {
                        append("Authorization", "Bearer ${userSession.authToken}")
                        append("Delta-Client", "${client.clientId}:${client.clientSecret}")
                    }
                    parameter("userEmail", disabledReceivingUser.email)
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
                testClient.post("/email/activation") {
                    headers {
                        append("Authorization", "Bearer ${adminSession.authToken}")
                        append("Delta-Client", "${client.clientId}:${client.clientSecret}")
                    }
                    parameter("userEmail", disabledReceivingSSOUser.email)
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
        testClient.post("/email/reset-password") {
            headers {
                append("Authorization", "Bearer ${adminSession.authToken}")
                append("Delta-Client", "${client.clientId}:${client.clientSecret}")
            }
            parameter("userEmail", enabledReceivingUser.email)
        }.apply {
            assertEquals(HttpStatusCode.OK, status)
            coVerify(exactly = 1) {
                emailService.sendResetPasswordEmail(enabledReceivingUser, "token", adminSession, any())
            }
            coVerify(exactly = 1) { resetPasswordTokenService.createToken(any()) }
        }
    }

    @Test
    fun testReadOnlyAdminSendResetPasswordEmail() = testSuspend {
        testClient.post("/email/reset-password") {
            headers {
                append("Authorization", "Bearer ${readOnlyAdminSession.authToken}")
                append("Delta-Client", "${client.clientId}:${client.clientSecret}")
            }
            parameter("userEmail", enabledReceivingUser.email)
        }.apply {
            assertEquals(HttpStatusCode.OK, status)
            coVerify(exactly = 1) {
                emailService.sendResetPasswordEmail(enabledReceivingUser, "token", readOnlyAdminSession, any())
            }
            coVerify(exactly = 1) { resetPasswordTokenService.createToken(any()) }
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
                    parameter("userEmail", disabledReceivingUser.email)
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
                testClient.post("/email/reset-password") {
                    headers {
                        append("Authorization", "Bearer ${userSession.authToken}")
                        append("Delta-Client", "${client.clientId}:${client.clientSecret}")
                    }
                    parameter("userEmail", enabledReceivingUser.email)
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
                testClient.post("/email/reset-password") {
                    headers {
                        append("Authorization", "Bearer ${adminSession.authToken}")
                        append("Delta-Client", "${client.clientId}:${client.clientSecret}")
                    }
                    parameter("userEmail", enabledReceivingSSOUser.email)
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
        coEvery { oauthSessionService.retrieveFromAuthToken(any(), client) } answers { null }
        coEvery {
            oauthSessionService.retrieveFromAuthToken(
                adminSession.authToken,
                client
            )
        } answers { adminSession }
        coEvery { oauthSessionService.retrieveFromAuthToken(userSession.authToken, client) } answers { userSession }
        coEvery {
            oauthSessionService.retrieveFromAuthToken(
                readOnlyAdminSession.authToken,
                client
            )
        } answers { readOnlyAdminSession }
        coEvery { userLookupService.lookupCurrentUser(adminSession) } returns adminUser
        coEvery { userLookupService.lookupCurrentUser(userSession) } returns regularUser
        coEvery { userLookupService.lookupCurrentUser(readOnlyAdminSession) } returns readOnlyAdminUser
        coEvery { userGUIDMapService.getGUIDFromEmail(enabledReceivingUser.email!!) } returns enabledReceivingUser.getGUID()
        coEvery { userGUIDMapService.getGUIDFromEmail(disabledReceivingUser.email!!) } returns disabledReceivingUser.getGUID()
        coEvery { userGUIDMapService.getGUIDFromEmail(enabledReceivingSSOUser.email!!) } returns enabledReceivingSSOUser.getGUID()
        coEvery { userGUIDMapService.getGUIDFromEmail(disabledReceivingSSOUser.email!!) } returns disabledReceivingSSOUser.getGUID()
        coEvery { userLookupService.lookupUserByGUID(enabledReceivingUser.getGUID()) } returns enabledReceivingUser
        coEvery { userLookupService.lookupUserByGUID(enabledReceivingSSOUser.getGUID()) } returns enabledReceivingSSOUser
        coEvery { userLookupService.lookupUserByGUID(disabledReceivingUser.getGUID()) } returns disabledReceivingUser
        coEvery { userLookupService.lookupUserByGUID(disabledReceivingSSOUser.getGUID()) } returns disabledReceivingSSOUser
        coEvery { resetPasswordTokenService.createToken(any()) } returns "token"
        coEvery { setPasswordTokenService.createToken(any()) } returns "token"
        coEvery {
            emailService.sendSetPasswordEmail(disabledReceivingUser, "token", adminSession, any())
        } just runs
        coEvery {
            emailService.sendResetPasswordEmail(enabledReceivingUser, "token", adminSession, any())
        } just runs
        coEvery {
            emailService.sendSetPasswordEmail(disabledReceivingUser, "token", readOnlyAdminSession, any())
        } just runs
        coEvery {
            emailService.sendResetPasswordEmail(enabledReceivingUser, "token", readOnlyAdminSession, any())
        } just runs
    }

    companion object {
        private lateinit var testApp: TestApplication
        private lateinit var testClient: HttpClient
        private lateinit var controller: AdminEmailController

        private val oauthSessionService = mockk<OAuthSessionService>()
        private val userLookupService = mockk<UserLookupService>()
        private val userGUIDMapService = mockk<UserGUIDMapService>()
        private val resetPasswordTokenService = mockk<ResetPasswordTokenService>()
        private val setPasswordTokenService = mockk<SetPasswordTokenService>()
        private val emailService = mockk<EmailService>()

        private val client = testServiceClient()
        private val adminUser = testLdapUser(cn = "admin", memberOfCNs = listOf(DeltaSystemRole.ADMIN.adCn()))
        private val readOnlyAdminUser =
            testLdapUser(cn = "read-only-admin", memberOfCNs = listOf(DeltaSystemRole.READ_ONLY_ADMIN.adCn()))
        private val regularUser = testLdapUser(cn = "user", memberOfCNs = emptyList())

        private val enabledReceivingUser = testLdapUser(
            email = "enabled-receiving-user@test.com",
            cn = LDAPConfig.emailToCN("enabled-receiving-user@test.com"),
            accountEnabled = true
        )
        private val enabledReceivingSSOUser = testLdapUser(
            email = "enabled-receiving-user@sso.domain",
            cn = LDAPConfig.emailToCN("enabled-receiving-user@sso.domain"),
            accountEnabled = true
        )
        private val disabledReceivingUser = testLdapUser(
            email = "disabled-receiving-user@test.com",
            cn = LDAPConfig.emailToCN("disabled-receiving-user@test.com"),
            accountEnabled = false
        )
        private val disabledReceivingSSOUser = testLdapUser(
            email = "disabled-receiving-user@sso.domain",
            cn = LDAPConfig.emailToCN("disabled-receiving-user@sso.domain"),
            accountEnabled = false
        )
        private val adminSession = OAuthSession(
            1, adminUser.cn, adminUser.getGUID(), client, "adminAccessToken", Instant.now(), "trace", false
        )
        private val readOnlyAdminSession =
            OAuthSession(
                1,
                readOnlyAdminUser.cn,
                readOnlyAdminUser.getGUID(),
                client,
                "readOnlyAdminAccessToken",
                Instant.now(),
                "trace",
                false
            )
        private val userSession = OAuthSession(
            1, regularUser.cn, regularUser.getGUID(), client, "userAccessToken", Instant.now(), "trace", false
        )

        @BeforeClass
        @JvmStatic
        fun setup() {
            controller = AdminEmailController(
                AzureADSSOConfig(listOf(AzureADSSOClient("dev", "", "", "", "@sso.domain", required = true))),
                emailService,
                userLookupService,
                userGUIDMapService,
                setPasswordTokenService,
                resetPasswordTokenService,
            )

            testApp = TestApplication {
                application {
                    configureSerialization()
                    authentication {
                        bearer(OAUTH_ACCESS_BEARER_TOKEN_AUTH_NAME) {
                            realm = "auth-service"
                            authenticate { oauthSessionService.retrieveFromAuthToken(it.token, client) }
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
