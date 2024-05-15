package uk.gov.communities.delta.controllers

import io.ktor.client.*
import io.ktor.client.plugins.contentnegotiation.*
import io.ktor.client.request.*
import io.ktor.http.*
import io.ktor.serialization.kotlinx.json.*
import io.ktor.server.application.*
import io.ktor.server.routing.*
import io.ktor.server.testing.*
import io.ktor.test.dispatcher.*
import io.mockk.*
import kotlinx.coroutines.runBlocking
import org.junit.*
import uk.gov.communities.delta.auth.controllers.external.ExternalDeltaApiTokenController
import uk.gov.communities.delta.auth.plugins.ApiError
import uk.gov.communities.delta.auth.plugins.configureSerialization
import uk.gov.communities.delta.auth.security.IADLdapLoginService
import uk.gov.communities.delta.auth.services.DeltaApiTokenService
import uk.gov.communities.delta.helper.testLdapUser
import uk.gov.communities.delta.helper.testServiceClient
import kotlin.test.assertEquals

class ExternalDeltaApiTokenControllerTest {
    @Test
    fun testCreateApiToken() = testSuspend {
        testClient.post("/delta-api/oauth/token") {
            contentType(ContentType.Application.Json)
            setBody("""
                {"grant_type": "${validGrantType}",
                "username": "${testUser.cn}",
                "password": "${validUserPassword}",
                "client_id": "${validClientId}",
                "client_secret": "${validClientSecret}"}
            """.trimIndent())
        }.apply {
            assertEquals(HttpStatusCode.OK, status)
            coVerify(exactly = 1) {
                tokenService.validateApiClientIdAndSecret(validClientId, validClientSecret)
            }
            coVerify(exactly = 1) {
                tokenService.createAndStoreApiToken(testUser.cn, validClientId)
            }
            confirmVerified(tokenService)
        }
    }

    @Test
    fun grantTypeMustBePassword() = testSuspend {
        Assert.assertThrows(ApiError::class.java) {
            runBlocking {
                testClient.post("/delta-api/oauth/token") {
                    contentType(ContentType.Application.Json)
                    setBody("""
                        {"grant_type": "device_code",
                        "username": "${testUser.cn}",
                        "password": "${validUserPassword}",
                        "client_id": "${validClientId}",
                        "client_secret": "${validClientSecret}"}
                    """.trimIndent())
                }
            }
        }.apply {
            assertEquals("invalid_grant_type", errorCode)
            coVerify(exactly = 0) { tokenService.createAndStoreApiToken(any(), any()) }
        }
    }

    @Test
    fun userCredentialsMustBeValid() = testSuspend {
        Assert.assertThrows(ApiError::class.java) {
            runBlocking {
                testClient.post("/delta-api/oauth/token") {
                    contentType(ContentType.Application.Json)
                    setBody("""
                        {"grant_type": "${validGrantType}",
                        "username": "${testUser.cn}",
                        "password": "wrong_password",
                        "client_id": "${validClientId}",
                        "client_secret": "${validClientSecret}"}
                    """.trimIndent())
                }
            }
        }.apply {
            assertEquals("invalid_credentials", errorCode)
            coVerify(exactly = 0) { tokenService.createAndStoreApiToken(any(), any()) }
        }
    }

    @Test
    fun clientCredentialsMustBeValid() = testSuspend {
        Assert.assertThrows(ApiError::class.java) {
            runBlocking {
                testClient.post("/delta-api/oauth/token") {
                    contentType(ContentType.Application.Json)
                    setBody("""
                        {"grant_type": "${validGrantType}",
                        "username": "${testUser.cn}",
                        "password": "${validUserPassword}",
                        "client_id": "${validClientId}",
                        "client_secret": "wrong_secret"}
                    """.trimIndent())
                }
            }
        }.apply {
            assertEquals("invalid_credentials", errorCode)
            coVerify(exactly = 0) { tokenService.createAndStoreApiToken(any(), any()) }
        }
    }

    @Before
    fun resetMocks() {
        clearAllMocks()
        coEvery { ldapService.ldapLogin(any(), any()) } returns IADLdapLoginService.UnknownAuthenticationFailure
        coEvery { ldapService.ldapLogin(testUser.cn, validUserPassword) } returns IADLdapLoginService.LdapLoginSuccess(
            testUser)
        coEvery { tokenService.validateApiClientIdAndSecret(any(), any()) } returns false
        coEvery { tokenService.validateApiClientIdAndSecret(validClientId, validClientSecret) } returns true
        coEvery { tokenService.createAndStoreApiToken(any(), any()) } returns "newApiToken"
    }

    companion object {
        private lateinit var testApp: TestApplication
        private lateinit var testClient: HttpClient
        private lateinit var controller: ExternalDeltaApiTokenController

        private val tokenService = mockk<DeltaApiTokenService>()
        private val ldapService = mockk<IADLdapLoginService>()

        private val testUser = testLdapUser()

        private val validGrantType = "password"
        private val validUserPassword = "test_password"
        private val validClientId = "id"
        private val validClientSecret = "correct_password"

        @BeforeClass
        @JvmStatic
        fun setup() {
            controller = ExternalDeltaApiTokenController(tokenService, ldapService)

            testApp = TestApplication {
                application {
                    configureSerialization()
                    routing {
                        route("/delta-api/oauth/token") {
                            controller.route(this)
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