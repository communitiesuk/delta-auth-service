package uk.gov.communities.delta.controllers

import io.ktor.client.*
import io.ktor.client.plugins.contentnegotiation.*
import io.ktor.client.request.*
import io.ktor.client.statement.*
import io.ktor.http.*
import io.ktor.serialization.kotlinx.json.*
import io.ktor.server.auth.*
import io.ktor.server.routing.*
import io.ktor.server.testing.*
import io.ktor.test.dispatcher.*
import io.mockk.*
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.jsonObject
import org.junit.*
import uk.gov.communities.delta.auth.config.Client
import uk.gov.communities.delta.auth.config.SAMLConfig
import uk.gov.communities.delta.auth.controllers.internal.InternalDeltaApiTokenController
import uk.gov.communities.delta.auth.plugins.ApiError
import uk.gov.communities.delta.auth.plugins.configureSerialization
import uk.gov.communities.delta.auth.saml.SAMLTokenService
import uk.gov.communities.delta.auth.security.CLIENT_HEADER_AUTH_NAME
import uk.gov.communities.delta.auth.security.clientHeaderAuth
import uk.gov.communities.delta.auth.services.DeltaApiTokenService
import uk.gov.communities.delta.auth.services.UserLookupService
import uk.gov.communities.delta.helper.testLdapUser
import java.util.*
import kotlin.test.assertEquals
import kotlin.test.assertNotNull

class InternalDeltaApiTokenControllerTest {
    @Test
    fun testValidateApiToken() = testSuspend {
        testClient.post("/internal/delta-api/validate") {
            headers {
                append(HttpHeaders.Accept, "application/json")
                append("Delta-Client", "${serviceClient.clientId}:${serviceClient.clientSecret}")
            }
            contentType(ContentType.Application.Json)
            setBody("{\"token\": \"${apiToken}\"}")
        }.apply {
            assertEquals(HttpStatusCode.OK, status)
            val json = Json.parseToJsonElement(bodyAsText())
            assertNotNull(json.jsonObject["token"])
            assertEquals(samlToken, extractJsonValue(json, "token"))
            assertEquals(testUser.cn, extractJsonValue(json, "username"))
            assertEquals(testUserClientId, extractJsonValue(json, "clientId"))
            assertEquals(testUser.javaUUIDObjectGuid, extractJsonValue(json, "userGuid"))
            coVerify(exactly = 1) {
                tokenService.validateApiToken(apiToken)
            }
            coVerify(exactly = 1) {
                samlTokenService.generate(serviceClient.samlCredential, testUser, any(), any())
            }
            confirmVerified(tokenService)
        }
    }

    @Test
    fun testInvalidApiToken() = testSuspend {
        Assert.assertThrows(ApiError::class.java) {
            runBlocking {
                testClient.post("/internal/delta-api/validate") {
                    headers {
                        append(HttpHeaders.Accept, "application/json")
                        append("Delta-Client", "${serviceClient.clientId}:${serviceClient.clientSecret}")
                    }
                    contentType(ContentType.Application.Json)
                    setBody("{\"token\": \"invalid_token\"}")
                }
            }
        }.apply {
            assertEquals("invalid_api_token", errorCode)
            confirmVerified(samlTokenService)
        }
    }

    @Before
    fun resetMocks() {
        clearAllMocks()
        coEvery { tokenService.validateApiToken(any()) } returns null
        coEvery { tokenService.validateApiToken(apiToken)} returns Triple(testUser.cn, testUserClientId, testUser.getGUID())
        coEvery { userLookupService.lookupUserByCN(testUser.cn) } returns testUser
        coEvery { samlTokenService.generate(serviceClient.samlCredential, testUser, any(), any())} returns samlToken
    }

    companion object {
        private lateinit var testApp: TestApplication
        private lateinit var testClient: HttpClient
        private lateinit var controller: InternalDeltaApiTokenController

        private val tokenService = mockk<DeltaApiTokenService>()
        private val samlTokenService = mockk<SAMLTokenService>()
        private val userLookupService = mockk<UserLookupService>()

        private val apiToken = "valid_api_token"
        private val samlToken = "saml_token"

        private val testUser = testLdapUser()
        private val testUserClientId = "client_id"

        private val serviceClient = Client("test-client", "test-secret", SAMLConfig.insecureHardcodedCredentials())

        @BeforeClass
        @JvmStatic
        fun setup() {
            controller = InternalDeltaApiTokenController(tokenService, samlTokenService, userLookupService)

            testApp = TestApplication {
                application {
                    configureSerialization()
                    authentication {
                        clientHeaderAuth(CLIENT_HEADER_AUTH_NAME) {
                            headerName = "Delta-Client"
                            clients = listOf(serviceClient)
                        }
                    }
                    routing {
                        authenticate(CLIENT_HEADER_AUTH_NAME, strategy = AuthenticationStrategy.Required) {
                            route("/internal/delta-api/validate") {
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

    private fun extractJsonValue(json: JsonElement, elementName: String): String {
        return json.jsonObject[elementName]!!.toString().removePrefix("\"").removeSuffix("\"")
    }
}
