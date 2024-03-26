package uk.gov.communities.delta.controllers

import io.ktor.client.*
import io.ktor.client.plugins.contentnegotiation.*
import io.ktor.client.request.*
import io.ktor.http.*
import io.ktor.serialization.kotlinx.json.*
import io.ktor.server.auth.*
import io.ktor.server.routing.*
import io.ktor.server.testing.*
import io.ktor.test.dispatcher.*
import io.mockk.*
import kotlinx.coroutines.runBlocking
import org.junit.*
import uk.gov.communities.delta.auth.config.DeltaConfig
import uk.gov.communities.delta.auth.controllers.internal.AdminEditEmailController
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

class AdminEditEmailControllerTest {
    @Test
    fun canUpdateEmailForUser() = testSuspend {
        testClient.post("/admin/update-user-email") {
            headers {
                append("Authorization", "Bearer ${adminSession.authToken}")
                append("Delta-Client", "${client.clientId}:${client.clientSecret}")
            }
            contentType(ContentType.Application.Json)
            setBody("{\"userToEditCn\": \"test!user.com\", " +
                "\"newEmail\": \"toast!user.com\"}")
        }.apply {
            assertEquals(HttpStatusCode.OK, status)
            coVerify(exactly = 1) {
                userService.updateEmail(userToUpdate, "toast!user.com", adminSession, any())
            }
            confirmVerified(userService)
        }
    }

    @Test
    fun nonAdminCannotUpdateEmail() = testSuspend {
        Assert.assertThrows(ApiError::class.java) {
            runBlocking {
                testClient.post("/admin/update-user-email") {
                    headers {
                        append("Authorization", "Bearer ${nonAdminSession.authToken}")
                        append("Delta-Client", "${client.clientId}:${client.clientSecret}")
                    }
                    contentType(ContentType.Application.Json)
                    setBody("{\"userToEditCn\": \"test!user.com\", " +
                        "\"newEmail\": \"toast!user.com\"}")
                }
            }
        }.apply {
            assertEquals("forbidden", errorCode)
            coVerify(exactly = 0) {
                userService.updateEmail(any(), any(), any(), any())
            }
            confirmVerified(userService)
        }
    }

    @Test
    fun cannotUpdateToBlankEmail() = testSuspend {
        Assert.assertThrows(ApiError::class.java) {
            runBlocking {
                testClient.post("/admin/update-user-email") {
                    headers {
                        append("Authorization", "Bearer ${adminSession.authToken}")
                        append("Delta-Client", "${client.clientId}:${client.clientSecret}")
                    }
                    contentType(ContentType.Application.Json)
                    setBody("{\"userToEditCn\": \"test!user.com\", " +
                        "\"newEmail\": \"\"}")
                }
            }
        }.apply {
            assertEquals("empty_username", errorCode)
            coVerify(exactly = 0) { userService.updateEmail(any(), any(), any(), any()) }
        }
    }

    @Before
    fun resetMocks() {
        clearAllMocks()
        coEvery {
            oauthSessionService.retrieveFomAuthToken(
                adminSession.authToken,
                client
            )
        } answers { adminSession }
        coEvery {
            oauthSessionService.retrieveFomAuthToken(
                nonAdminSession.authToken,
                client
            )
        } answers { nonAdminSession }
        coEvery { userLookupService.lookupUserByCn(userToUpdate.cn) } returns userToUpdate
        coEvery { userLookupService.lookupUserByCn(adminUser.cn) } returns adminUser
        coEvery { userLookupService.lookupUserByCn(nonAdminUser.cn) } returns nonAdminUser
        coEvery { userService.updateEmail(userToUpdate, any(), any(), any()) } just runs
    }

    companion object {
        private lateinit var testApp: TestApplication
        private lateinit var testClient: HttpClient
        private lateinit var controller: AdminEditEmailController

        private val oauthSessionService = mockk<OAuthSessionService>()

        private val userLookupService = mockk<UserLookupService>()
        private val userService = mockk<UserService>()

        private val client = testServiceClient()

        private val adminUser = testLdapUser(cn = "admin", memberOfCNs = listOf(DeltaConfig.DATAMART_DELTA_ADMIN))
        private val nonAdminUser = testLdapUser(cn = "nonadmin", memberOfCNs = listOf(DeltaConfig.DATAMART_DELTA_USER))

        private val userToUpdate = testLdapUser(
            cn = "test!user.com",
            email = "test@user.com",
            memberOfCNs = listOf(
                DeltaConfig.DATAMART_DELTA_USER,
            ),
        )

        private val adminSession = OAuthSession(1, adminUser.cn, client, "adminToken", Instant.now(), "trace", false)
        private val nonAdminSession = OAuthSession(1, nonAdminUser.cn, client, "nonAdminToken", Instant.now(), "trace", false)

        @BeforeClass
        @JvmStatic
        fun setup() {
            controller = AdminEditEmailController(
                userLookupService,
                userService,
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
                            route("/admin/update-user-email") {
                                controller.route(this)
                            }
                        }
                    }
                }
            }

            testClient = testApp.createClient {
                install(ContentNegotiation) {
                    json()
                }
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
