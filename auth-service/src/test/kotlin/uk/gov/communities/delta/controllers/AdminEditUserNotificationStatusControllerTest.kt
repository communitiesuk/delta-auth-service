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
import uk.gov.communities.delta.auth.controllers.internal.AdminEditUserNotificationStatusController
import uk.gov.communities.delta.auth.plugins.ApiError
import uk.gov.communities.delta.auth.plugins.configureSerialization
import uk.gov.communities.delta.auth.security.*
import uk.gov.communities.delta.auth.services.*
import uk.gov.communities.delta.auth.withBearerTokenAuth
import uk.gov.communities.delta.helper.mockUserLookupService
import uk.gov.communities.delta.helper.testLdapUser
import uk.gov.communities.delta.helper.testServiceClient
import java.time.Instant
import kotlin.test.assertEquals

class AdminEditUserNotificationStatusControllerTest {

    @Test
    fun fullAdminCanUpdateUserNotificationStatus() = testSuspend {
        testClient.post("/admin/update-notification-status") {
            headers {
                append("Authorization", "Bearer ${fullAdminSession.authToken}")
                append("Delta-Client", "${client.clientId}:${client.clientSecret}")
            }
            contentType(ContentType.Application.Json)
            setBody("{\"userToEditCn\": \"test!user.com\", " +
                "\"enableNotifications\": true}")
        }.apply {
            assertEquals(HttpStatusCode.OK, status)
            coVerify(exactly = 1) {
                userService.updateNotificationStatus(userToUpdate, true, fullAdminSession, any())
            }
            confirmVerified(userService)
        }
    }

    @Test
    fun readOnlyAdminCanUpdateUserNotificationStatus() = testSuspend {
        testClient.post("/admin/update-notification-status") {
            headers {
                append("Authorization", "Bearer ${readOnlyAdminSession.authToken}")
                append("Delta-Client", "${client.clientId}:${client.clientSecret}")
            }
            contentType(ContentType.Application.Json)
            setBody("{\"userToEditCn\": \"test!user.com\", " +
                "\"enableNotifications\": false}")
        }.apply {
            assertEquals(HttpStatusCode.OK, status)
            coVerify(exactly = 1) {
                userService.updateNotificationStatus(userToUpdate, false, readOnlyAdminSession, any())
            }
            confirmVerified(userService)
        }
    }

    @Test
    fun nonAdminCannotUpdateNotificationStatus() = testSuspend {
        Assert.assertThrows(ApiError::class.java) {
            runBlocking {
                testClient.post("/admin/update-notification-status") {
                    headers {
                        append("Authorization", "Bearer ${nonAdminSession.authToken}")
                        append("Delta-Client", "${client.clientId}:${client.clientSecret}")
                    }
                    contentType(ContentType.Application.Json)
                    setBody("{\"userToEditCn\": \"test!user.com\", " +
                        "\"enableNotifications\": false}")
                }
            }
        }.apply {
            assertEquals("forbidden", errorCode)
            confirmVerified(userService)
        }
    }

    @Before
    fun resetMocks() {
        clearAllMocks()
        coEvery {
            oauthSessionService.retrieveFomAuthToken(
                fullAdminSession.authToken,
                client
            )
        } answers { fullAdminSession }
        coEvery {
            oauthSessionService.retrieveFomAuthToken(
                readOnlyAdminSession.authToken,
                client
            )
        } answers { readOnlyAdminSession }
        coEvery {
            oauthSessionService.retrieveFomAuthToken(
                nonAdminSession.authToken,
                client
            )
        } answers { nonAdminSession }
        mockUserLookupService(
            userLookupService, listOf(
                Pair(fullAdminUser, fullAdminSession),
                Pair(readOnlyAdminUser, readOnlyAdminSession),
                Pair(nonAdminUser, nonAdminSession),
                Pair(userToUpdate, null)
            ), organisations = listOf(), accessGroups = listOf()
        )
        coEvery { userService.updateNotificationStatus(userToUpdate, any(), any(), any()) } just runs
    }

    companion object {
        private lateinit var testApp: TestApplication
        private lateinit var testClient: HttpClient
        private lateinit var controller: AdminEditUserNotificationStatusController

        private val oauthSessionService = mockk<OAuthSessionService>()

        private val userLookupService = mockk<UserLookupService>()
        private val userService = mockk<UserService>()

        private val client = testServiceClient()

        private val fullAdminUser = testLdapUser(cn = "admin", memberOfCNs = listOf(DeltaConfig.DATAMART_DELTA_ADMIN))
        private val readOnlyAdminUser = testLdapUser(cn = "readonlyadmin", memberOfCNs = listOf(DeltaConfig.DATAMART_DELTA_READ_ONLY_ADMIN))
        private val nonAdminUser = testLdapUser(cn = "nonadmin", memberOfCNs = listOf(DeltaConfig.DATAMART_DELTA_USER))

        private val userToUpdate = testLdapUser(
            cn = "test!user.com",
            email = "test@user.com",
            memberOfCNs = listOf(
                DeltaConfig.DATAMART_DELTA_USER,
            ),
        )

        private val fullAdminSession = OAuthSession(
            1,
            fullAdminUser.cn,
            fullAdminUser.getUUID(),
            client,
            "fullAdminToken",
            Instant.now(),
            "trace",
            false
        )
        private val readOnlyAdminSession = OAuthSession(
            1,
            readOnlyAdminUser.cn,
            readOnlyAdminUser.getUUID(),
            client,
            "readOnlyAdminToken",
            Instant.now(),
            "trace",
            false
        )
        private val nonAdminSession = OAuthSession(
            1,
            nonAdminUser.cn,
            nonAdminUser.getUUID(),
            client,
            "nonAdminToken",
            Instant.now(),
            "trace",
            false
        )

        @BeforeClass
        @JvmStatic
        fun setup() {
            controller = AdminEditUserNotificationStatusController(
                userLookupService,
                userService,
            )

            testApp = TestApplication {
                application {
                    configureSerialization()
                    authentication {
                        bearer(OAUTH_ACCESS_BEARER_TOKEN_AUTH_NAME) {
                            realm = "auth-service"
                            authenticate { oauthSessionService.retrieveFomAuthToken(it.token,
                                client
                            ) }
                        }
                        clientHeaderAuth(CLIENT_HEADER_AUTH_NAME) {
                            headerName = "Delta-Client"
                            clients = listOf(testServiceClient())
                        }
                    }
                    routing {
                        withBearerTokenAuth {
                            route("/admin/update-notification-status") {
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
