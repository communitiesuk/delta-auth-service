package uk.gov.communities.delta.controllers

import io.ktor.client.*
import io.ktor.client.request.*
import io.ktor.client.statement.*
import io.ktor.http.*
import io.ktor.server.application.*
import io.ktor.server.auth.*
import io.ktor.server.routing.*
import io.ktor.server.testing.*
import io.ktor.test.dispatcher.*
import io.mockk.*
import kotlinx.coroutines.runBlocking
import org.junit.*
import uk.gov.communities.delta.auth.config.AzureADSSOClient
import uk.gov.communities.delta.auth.config.AzureADSSOConfig
import uk.gov.communities.delta.auth.config.DeltaConfig
import uk.gov.communities.delta.auth.controllers.internal.AdminEnableDisableUserController
import uk.gov.communities.delta.auth.plugins.ApiError
import uk.gov.communities.delta.auth.plugins.configureSerialization
import uk.gov.communities.delta.auth.repositories.LdapUser
import uk.gov.communities.delta.auth.security.CLIENT_HEADER_AUTH_NAME
import uk.gov.communities.delta.auth.security.OAUTH_ACCESS_BEARER_TOKEN_AUTH_NAME
import uk.gov.communities.delta.auth.security.clientHeaderAuth
import uk.gov.communities.delta.auth.services.*
import uk.gov.communities.delta.auth.withBearerTokenAuth
import uk.gov.communities.delta.helper.testLdapUser
import uk.gov.communities.delta.helper.testServiceClient
import java.time.Instant
import kotlin.test.assertEquals

class AdminEnableDisableUserControllerTest {

    @Test
    fun testEnableUser() = testSuspend {
        val user = testLdapUser(cn = "user!example.com", accountEnabled = false)
        coEvery { userGUIDMapService.getGUIDFromCN(user.cn) } returns user.getGUID()
        coEvery { userLookupService.lookupUserByGUID(user.getGUID()) } returns user

        enableRequestAsAdminUser(user).apply {
            assertEquals(HttpStatusCode.OK, status)
            coVerify(exactly = 1) { userService.enableAccountAndNotifications(user.dn) }
            coVerify(exactly = 1) {
                auditService.userEnableAudit(user.getGUID(), adminUser.getGUID(), any())
            }
            confirmVerified(userService, auditService)
        }
    }

    @Test
    fun testUserAlreadyEnabled() = testSuspend {
        val user = testLdapUser(cn = "user!example.com", accountEnabled = true)
        coEvery { userGUIDMapService.getGUIDFromCN(user.cn) } returns user.getGUID()
        coEvery { userLookupService.lookupUserByGUID(user.getGUID()) } returns user

        enableRequestAsAdminUser(user).apply {
            assertEquals(HttpStatusCode.OK, status)
            confirmVerified(userService, auditService)
        }
    }

    @Test
    fun testUserNoPassword() {
        val user = testLdapUser(cn = "user!example.com", passwordLastSet = null, accountEnabled = false)
        coEvery { userGUIDMapService.getGUIDFromCN(user.cn) } returns user.getGUID()
        coEvery { userLookupService.lookupUserByGUID(user.getGUID()) } returns user

        Assert.assertThrows(ApiError::class.java) {
            runBlocking {
                enableRequestAsAdminUser(user)
            }
        }.apply {
            assertEquals("cannot_enable_user_no_password", errorCode)
            confirmVerified(userService, auditService)
        }
    }

    @Test
    fun testSSOUserNoPassword() = testSuspend {
        val user = testLdapUser(
            cn = "user!sso.domain",
            email = "user@sso.domain",
            passwordLastSet = null,
            accountEnabled = false
        )
        coEvery { userGUIDMapService.getGUIDFromCN(user.cn) } returns user.getGUID()
        coEvery { userLookupService.lookupUserByGUID(user.getGUID()) } returns user

        enableRequestAsAdminUser(user).apply {
            assertEquals(HttpStatusCode.OK, status)
            coVerify(exactly = 1) { userService.setPasswordAndEnableAccountAndNotifications(user.dn, any()) }
            coVerify(exactly = 1) { auditService.userEnableAudit(user.getGUID(), adminUser.getGUID(), any()) }
            confirmVerified(userService, auditService)
        }
    }

    @Test
    fun testCannotEnableUserAsNonAdmin() {
        val user = testLdapUser(cn = "user!example.com", accountEnabled = false)
        coEvery { userLookupService.lookupUserByGUID(user.getGUID()) } returns user

        Assert.assertThrows(ApiError::class.java) {
            runBlocking {
                testClient.post("/admin/enable-user") {
                    headers {
                        append("Authorization", "Bearer ${userSession.authToken}")
                        append("Delta-Client", "${client.clientId}:${client.clientSecret}")
                    }
                    parameter("userCn", user.cn)
                }
            }
        }.apply {
            assertEquals(HttpStatusCode.Forbidden, statusCode)
            confirmVerified(userService, auditService)
        }
    }

    @Test
    fun testDisableUser() = testSuspend {
        val user = testLdapUser(cn = "user!example.com")
        coEvery { userGUIDMapService.getGUIDFromCN(user.cn) } returns user.getGUID()
        coEvery { userLookupService.lookupUserByGUID(user.getGUID()) } returns user
        coEvery { setPasswordTokenService.clearTokenForUserGUID(user.getGUID()) } just runs

        disableRequestAsAdminUser(user).apply {
            assertEquals(HttpStatusCode.OK, status)
            coVerify(exactly = 1) { userService.disableAccountAndNotifications(user.dn) }
            coVerify(exactly = 1) { setPasswordTokenService.clearTokenForUserGUID(user.getGUID()) }
            coVerify(exactly = 1) {
                auditService.userDisableAudit(user.getGUID(), adminUser.getGUID(), any())
            }
            coVerify(exactly = 1) { setPasswordTokenService.clearTokenForUserGUID(user.getGUID()) }
            coVerify(exactly = 1) {
                auditService.userDisableAudit(user.getGUID(), adminUser.getGUID(), any())
            }
            confirmVerified(userService, auditService, setPasswordTokenService)
        }
    }

    @Test
    fun testUserAlreadyDisabled() = testSuspend {
        val user = testLdapUser(cn = "user!example.com", accountEnabled = false)
        coEvery { userGUIDMapService.getGUIDFromCN(user.cn) } returns user.getGUID()
        coEvery { userLookupService.lookupUserByGUID(user.getGUID()) } returns user
        disableRequestAsAdminUser(user).apply {
            assertEquals(HttpStatusCode.OK, status)
            confirmVerified(userService, auditService, setPasswordTokenService)
        }
    }

    @Test
    fun testCannotDisableUserAsNonAdmin() {
        val user = testLdapUser(cn = "user!example.com")
        coEvery { userLookupService.lookupUserByGUID(user.getGUID()) } returns user

        Assert.assertThrows(ApiError::class.java) {
            runBlocking {
                testClient.post("/admin/disable-user") {
                    headers {
                        append("Authorization", "Bearer ${userSession.authToken}")
                        append("Delta-Client", "${client.clientId}:${client.clientSecret}")
                    }
                    parameter("userCn", user.cn)
                }
            }
        }.apply {
            assertEquals(HttpStatusCode.Forbidden, statusCode)
            confirmVerified(userService, auditService, setPasswordTokenService)
        }
    }

    private suspend fun enableRequestAsAdminUser(user: LdapUser): HttpResponse {
        return testClient.post("/admin/enable-user") {
            headers {
                append("Authorization", "Bearer ${adminSession.authToken}")
                append("Delta-Client", "${client.clientId}:${client.clientSecret}")
            }
            parameter("userCn", user.cn)
        }
    }

    private suspend fun disableRequestAsAdminUser(user: LdapUser): HttpResponse {
        return testClient.post("/admin/disable-user") {
            headers {
                append("Authorization", "Bearer ${adminSession.authToken}")
                append("Delta-Client", "${client.clientId}:${client.clientSecret}")
            }
            parameter("userCn", user.cn)
        }
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

        coEvery { userLookupService.lookupCurrentUser(adminSession) } returns adminUser
        coEvery { userLookupService.lookupCurrentUser(userSession) } returns regularUser
        coEvery { auditService.userEnableAudit(any(), any(), any()) } just runs
        coEvery { auditService.userDisableAudit(any(), any(), any()) } just runs
    }

    companion object {
        private lateinit var testApp: TestApplication
        private lateinit var testClient: HttpClient
        private lateinit var controller: AdminEnableDisableUserController

        private lateinit var oauthSessionService: OAuthSessionService
        private lateinit var userLookupService: UserLookupService
        private lateinit var userGUIDMapService: UserGUIDMapService
        private lateinit var setPasswordTokenService: SetPasswordTokenService
        private lateinit var userService: UserService
        private lateinit var auditService: UserAuditService

        private val client = testServiceClient()
        private val adminUser = testLdapUser(cn = "admin", memberOfCNs = listOf(DeltaConfig.DATAMART_DELTA_ADMIN))
        private val regularUser = testLdapUser(cn = "user", memberOfCNs = emptyList())

        private val adminSession =
            OAuthSession(
                1, adminUser.cn, adminUser.getGUID(), client, "adminAccessToken", Instant.now(), "trace", false
            )
        private val userSession =
            OAuthSession(
                1, regularUser.cn, adminUser.getGUID(), client, "userAccessToken", Instant.now(), "trace", false
            )

        @BeforeClass
        @JvmStatic
        fun setup() {
            oauthSessionService = mockk<OAuthSessionService>()
            userLookupService = mockk<UserLookupService>()
            userGUIDMapService = mockk<UserGUIDMapService>()
            setPasswordTokenService = mockk<SetPasswordTokenService>()
            userService = mockk<UserService>(relaxed = true)
            auditService = mockk<UserAuditService>()
            controller = AdminEnableDisableUserController(
                AzureADSSOConfig(listOf(AzureADSSOClient("dev", "", "", "", "@sso.domain", required = true))),
                userLookupService,
                userGUIDMapService,
                userService,
                setPasswordTokenService,
                auditService,
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
                            post("/admin/enable-user") {
                                controller.enableUser(call)
                            }
                            post("/admin/disable-user") {
                                controller.disableUser(call)
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
