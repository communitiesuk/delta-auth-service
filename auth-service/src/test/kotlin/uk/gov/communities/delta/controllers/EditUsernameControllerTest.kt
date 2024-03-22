package uk.gov.communities.delta.controllers

import io.ktor.client.*
import io.ktor.client.plugins.contentnegotiation.*
import io.ktor.client.request.*
import io.ktor.http.*
import io.ktor.http.headers
import io.ktor.serialization.kotlinx.json.*
import io.ktor.server.auth.*
import io.ktor.server.routing.*
import io.ktor.server.testing.*
import io.ktor.test.dispatcher.*
import io.mockk.*
import kotlinx.coroutines.runBlocking
import org.junit.*
import uk.gov.communities.delta.auth.config.DeltaConfig
import uk.gov.communities.delta.auth.controllers.internal.EditUsernameController
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
import kotlin.test.assertTrue

class EditUsernameControllerTest {
    @Test
    fun userCanUpdateUsername() = testSuspend {
        testClient.post("/username") {
            headers {
                append("Authorization", "Bearer ${testUserSession.authToken}")
                append("Delta-Client", "${client.clientId}:${client.clientSecret}")
            }
            contentType(ContentType.Application.Json)
            setBody("{\"username\": \"toast!user.com\"}")
        }.apply {
            assertEquals(HttpStatusCode.OK, status)
            coVerify(exactly = 1) {
                userService.updateUsername(testUser, "toast!user.com", null, any())
            }
            confirmVerified(userService)
        }
    }

    @Test
    fun userCannotChooseBlankUsername() = testSuspend {
        Assert.assertThrows(ApiError::class.java) {
            runBlocking {
                testClient.post("/username") {
                    headers {
                        append("Authorization", "Bearer ${testUserSession.authToken}")
                        append("Delta-Client", "${client.clientId}:${client.clientSecret}")
                    }
                    contentType(ContentType.Application.Json)
                    setBody("{\"username\": \"\"}")
                }
            }
        }.apply {
            assertEquals("empty_username", errorCode)
            coVerify(exactly = 0) { userService.updateUsername(any(), any(), any(), any()) }
        }
    }

    @Before
    fun resetMocks() {
        clearAllMocks()
        coEvery {
            oauthSessionService.retrieveFomAuthToken(
                testUserSession.authToken,
                client
            )
        } answers { testUserSession }
        coEvery { userLookupService.lookupUserByCn(testUser.cn) } returns testUser
        coEvery { userService.updateUsername(testUser, any(), null, any()) } just runs
    }

    companion object {
        private lateinit var testApp: TestApplication
        private lateinit var testClient: HttpClient
        private lateinit var controller: EditUsernameController

        private val oauthSessionService = mockk<OAuthSessionService>()

        private val userLookupService = mockk<UserLookupService>()
        private val userService = mockk<UserService>()

        private val client = testServiceClient()

        private val testUser = testLdapUser(
            cn = "test!user.com",
            email = "test@user.com",
            memberOfCNs = listOf(
                DeltaConfig.DATAMART_DELTA_USER,
            ),
            mobile = "0123456789",
            telephone = "0987654321",
        )

        private val testUserSession =
            OAuthSession(1, testUser.cn, client, "testUserToken", Instant.now(), "trace", false)

        @BeforeClass
        @JvmStatic
        fun setup() {
            controller = EditUsernameController(
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
                            route("/username") {
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
