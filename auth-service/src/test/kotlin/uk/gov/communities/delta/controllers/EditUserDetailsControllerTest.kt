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
import junit.framework.TestCase.assertTrue
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement
import org.junit.*
import uk.gov.communities.delta.auth.config.DeltaConfig
import uk.gov.communities.delta.auth.controllers.internal.EditUserDetailsController
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
import javax.naming.directory.DirContext
import javax.naming.directory.ModificationItem
import kotlin.test.assertEquals

class EditUserDetailsControllerTest {
    @Test
    fun userCanUpdateDetails() = testSuspend {
        testClient.post("/user-details") {
            headers {
                append("Authorization", "Bearer ${testUserSession.authToken}")
                append("Delta-Client", "${client.clientId}:${client.clientSecret}")
            }
            contentType(ContentType.Application.Json)
            setBody(getUserDetailsJson())
        }.apply {
            assertEquals(HttpStatusCode.OK, status)
            coVerify(exactly = 1) {
                userService.updateUser(testUser, capture(modifications), null, any())
            }

            assertEquals(4, modifications.captured.size)
            assertTrue(modifications.captured.any { it.modificationOp == DirContext.REMOVE_ATTRIBUTE && it.attribute.id == "telephoneNumber" })
            assertTrue(modifications.captured.any { it.modificationOp == DirContext.ADD_ATTRIBUTE && it.attribute.id == "title" && it.attribute.get() == "right" })
            assertTrue(modifications.captured.any { it.modificationOp == DirContext.REPLACE_ATTRIBUTE && it.attribute.id == "sn" && it.attribute.get() == "Surname Two" })
            assertTrue(modifications.captured.any { it.modificationOp == DirContext.REPLACE_ATTRIBUTE && it.attribute.id == "givenName" && it.attribute.get() == "Given Two" })

            confirmVerified(userService)
        }
    }

    @Test
    fun userCannotChooseNonNumericTelephoneNumber() = testSuspend {
        Assert.assertThrows(ApiError::class.java) {
            runBlocking {
                testClient.post("/user-details") {
                    headers {
                        append("Authorization", "Bearer ${testUserSession.authToken}")
                        append("Delta-Client", "${client.clientId}:${client.clientSecret}")
                    }
                    contentType(ContentType.Application.Json)
                    setBody(getInvalidUserDetailsJson())
                }
            }
        }.apply {
            assertEquals("non_numeric_telephone_number", errorCode)
            coVerify(exactly = 0) { userService.updateUser(any(), any(), any(), any()) }
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
        coEvery { userService.updateUser(testUser, any(), null, any()) } just runs
    }


    companion object {
        private lateinit var testApp: TestApplication
        private lateinit var testClient: HttpClient
        private lateinit var controller: EditUserDetailsController

        private val oauthSessionService = mockk<OAuthSessionService>()

        private val userLookupService = mockk<UserLookupService>()
        private val userService = mockk<UserService>()

        private val client = testServiceClient()

        private val testUser = testLdapUser(
            cn = "test!user.com",
            email = "test@user.com",
            lastName = "Surname One",
            firstName = "Given One",
            memberOfCNs = listOf(
                DeltaConfig.DATAMART_DELTA_USER,
            ),
            mobile = "0123456789",
            telephone = "0987654321",
        )
        private val modifications = slot<Array<ModificationItem>>()

        private fun getUserDetailsJson(): JsonElement {
            return Json.parseToJsonElement(
                "{\"lastName\":\"Surname Two\"," +
                    "\"firstName\":\"Given Two\"," +
                    "\"position\":\"right\"}"
            )
        }
        private fun getInvalidUserDetailsJson(): JsonElement {
            return Json.parseToJsonElement(
                "{\"lastName\":\"Surname Two\"," +
                    "\"firstName\":\"Given Two\"," +
                    "\"telephone\":\"onetwothreefour\"," +
                    "\"position\":\"right\"}"
            )
        }

        private val testUserSession =
            OAuthSession(1, testUser.cn, client, "testUserToken", Instant.now(), "trace", false)

        @BeforeClass
        @JvmStatic
        fun setup() {
            controller = EditUserDetailsController(
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
                            route("/user-details") {
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
