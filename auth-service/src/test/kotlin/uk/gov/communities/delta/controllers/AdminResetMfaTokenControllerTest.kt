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
import uk.gov.communities.delta.auth.controllers.internal.AdminResetMfaTokenController
import uk.gov.communities.delta.auth.plugins.ApiError
import uk.gov.communities.delta.auth.plugins.configureSerialization
import uk.gov.communities.delta.auth.security.CLIENT_HEADER_AUTH_NAME
import uk.gov.communities.delta.auth.security.OAUTH_ACCESS_BEARER_TOKEN_AUTH_NAME
import uk.gov.communities.delta.auth.security.clientHeaderAuth
import uk.gov.communities.delta.auth.services.OAuthSession
import uk.gov.communities.delta.auth.services.OAuthSessionService
import uk.gov.communities.delta.auth.services.UserLookupService
import uk.gov.communities.delta.auth.services.UserService
import uk.gov.communities.delta.auth.withBearerTokenAuth
import uk.gov.communities.delta.helper.mockUserLookupService
import uk.gov.communities.delta.helper.testLdapUser
import uk.gov.communities.delta.helper.testServiceClient
import java.time.Instant
import kotlin.test.assertEquals

class AdminResetMfaTokenControllerTest {

    @Test
    fun adminCanResetUserMfaToken() = testSuspend {
        testClient.post("/admin/reset-mfa-token") {
            headers {
                append("Authorization", "Bearer ${adminSession.authToken}")
                append("Delta-Client", "${client.clientId}:${client.clientSecret}")
            }
            contentType(ContentType.Application.Json)
            setBody("{\"userToEditCn\": \"test!user.com\"}")
        }.apply {
            assertEquals(HttpStatusCode.OK, status)
            coVerify(exactly = 1) {
                userService.resetMfaToken(userToUpdate, adminSession, any())
            }
            confirmVerified(userService)
        }
    }

    @Test
    fun nonAdminCannotResetUserMfaToken() = testSuspend {
        Assert.assertThrows(ApiError::class.java) {
            runBlocking {
                testClient.post("/admin/reset-mfa-token") {
                    headers {
                        append("Authorization", "Bearer ${nonFullAdminSession.authToken}")
                        append("Delta-Client", "${client.clientId}:${client.clientSecret}")
                    }
                    contentType(ContentType.Application.Json)
                    setBody("{\"userToEditCn\": \"test!user.com\"}")
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
                adminSession.authToken,
                client
            )
        } answers { adminSession }
        coEvery {
            oauthSessionService.retrieveFomAuthToken(
                nonFullAdminSession.authToken,
                client
            )
        } answers { nonFullAdminSession }
        mockUserLookupService(
            userLookupService, listOf(
                Pair(adminUser, adminSession),
                Pair(nonFullAdminUser, nonFullAdminSession),
                Pair(userToUpdate, null)
            ), listOf(), listOf()
        )
        coEvery { userService.resetMfaToken(userToUpdate, any(), any()) } just runs
    }

    companion object {
        private lateinit var testApp: TestApplication
        private lateinit var testClient: HttpClient
        private lateinit var controller: AdminResetMfaTokenController

        private val oauthSessionService = mockk<OAuthSessionService>()

        private val userLookupService = mockk<UserLookupService>()
        private val userService = mockk<UserService>()

        private val client = testServiceClient()

        private val adminUser = testLdapUser(cn = "admin", memberOfCNs = listOf(DeltaConfig.DATAMART_DELTA_ADMIN))
        private val nonFullAdminUser = testLdapUser(cn = "nonFullAdmin", memberOfCNs = listOf(
            DeltaConfig.DATAMART_DELTA_READ_ONLY_ADMIN,
            DeltaConfig.DATAMART_DELTA_USER,
            DeltaConfig.DATAMART_DELTA_INTERNAL_USER,
            DeltaConfig.DATAMART_DELTA_REPORT_USERS
        ))

        private val userToUpdate = testLdapUser(
            cn = "test!user.com",
            email = "test@user.com",
            memberOfCNs = listOf(
                DeltaConfig.DATAMART_DELTA_USER,
            ),
            deltaTOTPSecret = "TopOfThePops"
        )

        private val adminSession =
            OAuthSession(1, adminUser.cn, adminUser.getGUID(), client, "adminToken", Instant.now(), "trace", false)
        private val nonFullAdminSession = OAuthSession(
            1,
            nonFullAdminUser.cn,
            nonFullAdminUser.getGUID(),
            client,
            "readOnlyAdminToken",
            Instant.now(),
            "trace",
            false
        )

        @BeforeClass
        @JvmStatic
        fun setup() {
            controller = AdminResetMfaTokenController(
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
                            route("/admin/reset-mfa-token") {
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
