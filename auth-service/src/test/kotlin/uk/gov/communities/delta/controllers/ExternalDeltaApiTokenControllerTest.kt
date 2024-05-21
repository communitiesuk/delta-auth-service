package uk.gov.communities.delta.controllers

import io.ktor.client.*
import io.ktor.client.plugins.contentnegotiation.*
import io.ktor.client.request.*
import io.ktor.client.request.forms.*
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
        testClient.submitForm(
            url = "/delta-api/oauth/token",
            formParameters = parameters {
                append("grant_type", validGrantType)
                append("username", testUser.cn)
                append("password", validUserPassword)
                append("client_id", validClientId)
                append("client_secret", validClientSecret)
            }
        ).apply {
            assertEquals(HttpStatusCode.OK, status)
            coVerify(exactly = 1) {
                tokenService.validateApiClientIdAndSecret(validClientId, validClientSecret)
            }
            coVerify(exactly = 1) {
                tokenService.createAndStoreApiToken(testUser.cn, validClientId, testUser.javaUUIDObjectGuid, any())
            }
            confirmVerified(tokenService)
        }
    }

    @Test
    fun grantTypeMustBePassword() = testSuspend {
        Assert.assertThrows(ApiError::class.java) {
            runBlocking {
                testClient.submitForm(
                    url = "/delta-api/oauth/token",
                    formParameters = parameters {
                        append("grant_type", "device_code")
                        append("username", testUser.cn)
                        append("password", validUserPassword)
                        append("client_id", validClientId)
                        append("client_secret", validClientSecret)
                    }
                )
            }
        }.apply {
            assertEquals("invalid_grant_type", errorCode)
            coVerify(exactly = 0) { tokenService.createAndStoreApiToken(any(), any(), any(), any()) }
        }
    }

    @Test
    fun userCredentialsMustBeValid() = testSuspend {
        Assert.assertThrows(ApiError::class.java) {
            runBlocking {
                testClient.submitForm(
                    url = "/delta-api/oauth/token",
                    formParameters = parameters {
                        append("grant_type", validGrantType)
                        append("username", testUser.cn)
                        append("password", "wrong_password")
                        append("client_id", validClientId)
                        append("client_secret", validClientSecret)
                    }
                )
            }
        }.apply {
            assertEquals("invalid_grant", errorCode)
            coVerify(exactly = 0) { tokenService.createAndStoreApiToken(any(), any(), any(), any()) }
        }
    }

    @Test
    fun clientCredentialsMustBeValid() = testSuspend {
        Assert.assertThrows(ApiError::class.java) {
            runBlocking {
                testClient.submitForm(
                    url = "/delta-api/oauth/token",
                    formParameters = parameters {
                        append("grant_type", validGrantType)
                        append("username", testUser.cn)
                        append("password", validUserPassword)
                        append("client_id", validClientId)
                        append("client_secret", "wrong_secret")
                    }
                )
            }
        }.apply {
            assertEquals("invalid_client", errorCode)
            coVerify(exactly = 0) { tokenService.createAndStoreApiToken(any(), any(), any(), any()) }
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
        coEvery { tokenService.createAndStoreApiToken(any(), any(), any(), any()) } returns "newApiToken"
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
