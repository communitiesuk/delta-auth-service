package uk.gov.communities.delta.security

import io.ktor.client.*
import io.ktor.client.engine.mock.*
import io.ktor.client.plugins.cookies.*
import io.ktor.client.request.*
import io.ktor.client.statement.*
import io.ktor.http.*
import io.ktor.server.auth.*
import io.ktor.server.plugins.callid.*
import io.ktor.server.routing.*
import io.ktor.server.testing.*
import io.ktor.test.dispatcher.*
import io.ktor.util.*
import io.ktor.utils.io.*
import io.mockk.every
import io.mockk.mockk
import io.mockk.verify
import org.junit.AfterClass
import org.junit.BeforeClass
import org.junit.Test
import uk.gov.communities.delta.auth.config.*
import uk.gov.communities.delta.auth.controllers.external.DeltaLoginController
import uk.gov.communities.delta.auth.controllers.external.DeltaOAuthLoginController
import uk.gov.communities.delta.auth.deltaLoginRoutes
import uk.gov.communities.delta.auth.plugins.configureTemplating
import uk.gov.communities.delta.auth.security.OAuthClientProviderLookupService
import uk.gov.communities.delta.auth.security.SSOLoginStateService
import uk.gov.communities.delta.auth.security.configureRateLimiting
import uk.gov.communities.delta.auth.security.deltaOAuth
import uk.gov.communities.delta.auth.services.AuthCode
import uk.gov.communities.delta.auth.services.AuthorizationCodeService
import uk.gov.communities.delta.auth.services.MicrosoftGraphService
import uk.gov.communities.delta.auth.services.UserLookupService
import uk.gov.communities.delta.helper.testLdapUser
import uk.gov.communities.delta.helper.testServiceClient
import java.time.Instant
import kotlin.test.assertContains
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue


class OAuthLoginTest {

    @Test
    fun testOAuthFlow() = testSuspend {
        val testClient = testApp.createClient {
            install(HttpCookies)
            followRedirects = false
        }
        testClient.get("/delta/login?response_type=code&client_id=delta-website&state=delta-state").apply {
            assertEquals(HttpStatusCode.OK, status)
            assertContains(bodyAsText(), "Test SSO</a>")
        }

        val oauthLoginResponse = testClient.get("/delta/oauth/test/login").apply {
            assertEquals(HttpStatusCode.Found, status)
        }
        val externalServiceRedirect = oauthLoginResponse.headers["Location"]
        assertNotNull(externalServiceRedirect, "Location header expected")
        assertTrue(externalServiceRedirect.startsWith("https://login.microsoftonline.com/${ssoClient.azTenantId}/oauth2/v2.0/authorize"))
        assertContains(externalServiceRedirect, "client_id=${ssoClient.azClientId}")
        assertContains(
            externalServiceRedirect,
            "redirect_uri=${"http://auth-service/delta/oauth/test/callback".encodeURLParameter()}"
        )
        val state = Regex("state=([^&]+)[&$]").find(externalServiceRedirect)!!.groups[1]!!.value

        testClient.get("/delta/oauth/test/callback?code=auth-code&state=${state}").apply {
            assertEquals(HttpStatusCode.Found, status)
            assertEquals(headers["Location"], "https://delta/redirect?code=code&state=delta-state")
            verify { authorizationCodeServiceMock.generateAndStore("cn", serviceClient, any()) }
        }
    }

    companion object {
        private lateinit var testApp: TestApplication
        private val deltaConfig = DeltaConfig.fromEnv()
        private val serviceClient = testServiceClient()
        private val ssoClient = AzureADSSOClient(
            "test", "tenant-id", "sso-client-id", "sso-client-secret",
            buttonText = "Test SSO"
        )
        private val ssoConfig = AzureADSSOConfig(listOf(ssoClient))
        private val ldapUserLookupServiceMock = mockk<UserLookupService>()
        private val authorizationCodeServiceMock = mockk<AuthorizationCodeService>()
        private val microsoftGraphServiceMock = mockk<MicrosoftGraphService>()
        private val ssoLoginStateService = SSOLoginStateService()

        @BeforeClass
        @JvmStatic
        fun setup() {
            every { ldapUserLookupServiceMock.lookupUserByCn("user!example.com") } answers {
                testLdapUser(memberOfCNs = listOf(deltaConfig.requiredGroupCn))
            }
            every { authorizationCodeServiceMock.generateAndStore("cn", serviceClient, any()) } answers {
                AuthCode("code", "cn", serviceClient, Instant.MIN, "trace")
            }
            val loginPageController = DeltaLoginController(
                listOf(serviceClient),
                ssoConfig,
                deltaConfig,
                mockk(),
                authorizationCodeServiceMock
            )
            val oauthController = DeltaOAuthLoginController(
                deltaConfig,
                ClientConfig(listOf(serviceClient)),
                ssoConfig,
                ssoLoginStateService,
                ldapUserLookupServiceMock,
                authorizationCodeServiceMock,
                microsoftGraphServiceMock,
            )
            val oauthClientProviderLookupService = OAuthClientProviderLookupService(
                ssoConfig, ssoLoginStateService
            )
            val mockHttpEngine = MockEngine {
                respond(
                    content = ByteReadChannel(
                        """{
                                "access_token": "header.${"{\"email\": \"user@example.com\"}".encodeBase64()}.trailer",
                                "token_type": "Bearer",
                                "expires_in": 3599,
                                "scope": "Some.Scope"
                            }"""
                    ),
                    status = HttpStatusCode.OK,
                    headers = headersOf(HttpHeaders.ContentType, "application/json")
                )
            }
            testApp = TestApplication {
                install(CallId) { generate(4) }
                install(Authentication) {
                    deltaOAuth(
                        ServiceConfig("http://auth-service"),
                        HttpClient(mockHttpEngine),
                        oauthClientProviderLookupService,
                    )
                }
                application {
                    configureTemplating(false)
                    configureRateLimiting(10)
                    routing {
                        route("/delta") {
                            deltaLoginRoutes(loginPageController, oauthController)
                        }
                    }
                }
            }
        }

        @AfterClass
        @JvmStatic
        fun tearDown() {
            testApp.stop()
        }
    }
}
