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
import io.mockk.*
import kotlinx.coroutines.runBlocking
import org.hamcrest.CoreMatchers
import org.hamcrest.MatcherAssert
import org.junit.*
import uk.gov.communities.delta.auth.config.*
import uk.gov.communities.delta.auth.controllers.external.DeltaLoginController
import uk.gov.communities.delta.auth.controllers.external.DeltaSSOLoginController
import uk.gov.communities.delta.auth.deltaLoginRoutes
import uk.gov.communities.delta.auth.plugins.configureTemplating
import uk.gov.communities.delta.auth.services.sso.SSOOAuthClientProviderLookupService
import uk.gov.communities.delta.auth.services.sso.SSOLoginSessionStateService
import uk.gov.communities.delta.auth.security.configureRateLimiting
import uk.gov.communities.delta.auth.security.azureAdSingleSignOn
import uk.gov.communities.delta.auth.services.AuthCode
import uk.gov.communities.delta.auth.services.AuthorizationCodeService
import uk.gov.communities.delta.auth.services.sso.MicrosoftGraphService
import uk.gov.communities.delta.auth.services.UserLookupService
import uk.gov.communities.delta.helper.testLdapUser
import uk.gov.communities.delta.helper.testServiceClient
import java.time.Instant
import javax.naming.NameNotFoundException
import kotlin.test.assertContains
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue


class OAuthLoginTest {

    @Test
    fun testOAuthFlow() = testSuspend {
        val testClient = testClient()
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
        val state = externalServiceRedirect.stateFromRedirectUrl()

        testClient.get("/delta/oauth/test/callback?code=auth-code&state=${state}").apply {
            assertEquals(HttpStatusCode.Found, status)
            assertEquals(headers["Location"], "https://delta/redirect?code=code&state=delta-state")
            verify { authorizationCodeServiceMock.generateAndStore("cn", serviceClient, any()) }
            assertEquals("", setCookie()[0].value) // Session should be cleared
        }
    }

    @Test
    fun `Login endpoint throws error with no session cookie`() {
        Assert.assertThrows(DeltaSSOLoginController.OAuthLoginException::class.java) {
            runBlocking { testClient().get("/delta/oauth/test/login") }
        }.apply {
            assertEquals("reached_login_page", errorCode)
        }
    }

    // Shared cookie and state parameter as though the user had just been redirected to Azure
    private class LoginState(val cookie: Cookie, val state: String)

    private val loginState: LoginState by lazy {
        runBlocking {
            val client = testClient()
            client.get("/delta/login?response_type=code&client_id=delta-website&state=delta-state")
            val state = client.get("/delta/oauth/test/login").headers["Location"]!!.stateFromRedirectUrl()
            val cookie = client.cookies("http://localhost/")[0]
            LoginState(cookie, state)
        }
    }

    @Test
    fun `Callback endpoint redirects Azure errors to Delta`() = testSuspend {
        val client = testClient(loginState.cookie)
        client.get("/delta/oauth/test/callback?error=some_azure_error_code&error_description=Description&state=${loginState.state}")
            .apply {
                assertEquals(HttpStatusCode.Found, status)
                MatcherAssert.assertThat(
                    headers["Location"],
                    CoreMatchers.startsWith("${deltaConfig.deltaWebsiteUrl}/login?error=delta_sso_failed&sso_error=some_azure_error")
                )
                verify(exactly = 0) { authorizationCodeServiceMock.generateAndStore("cn", serviceClient, any()) }
            }
    }

    @Test
    fun `Callback returns error on invalid state`() {
        Assert.assertThrows(DeltaSSOLoginController.OAuthLoginException::class.java) {
            runBlocking { testClient(loginState.cookie).get("/delta/oauth/test/callback?code=auth-code&state=DIFFERENT-STATE") }
        }.apply {
            assertEquals("callback_invalid_state", errorCode)
        }
    }

    @Test
    fun `Callback redirects to Delta create user page if no ldap user`() = testSuspend {
        every { ldapUserLookupServiceMock.lookupUserByCn("user!example.com") } throws (NameNotFoundException())
        testClient(loginState.cookie).get("/delta/oauth/test/callback?code=auth-code&state=${loginState.state}")
            .apply {
                assertEquals(HttpStatusCode.Found, status)
                MatcherAssert.assertThat(
                    headers["Location"],
                    CoreMatchers.startsWith("${deltaConfig.deltaWebsiteUrl}/register")
                )
            }
    }

    @Test
    fun `Callback returns error if user is disabled`()  {
        every { ldapUserLookupServiceMock.lookupUserByCn("user!example.com") } answers {
            testLdapUser(memberOfCNs = listOf(deltaConfig.requiredGroupCn), accountEnabled = false)
        }
        Assert.assertThrows(DeltaSSOLoginController.OAuthLoginException::class.java) {
            runBlocking { testClient(loginState.cookie).get("/delta/oauth/test/callback?code=auth-code&state=${loginState.state}") }
        }.apply {
            assertEquals("user_disabled", errorCode)
        }
    }

    @Test
    fun `Callback returns error if user is not in Delta users group`()  {
        every { ldapUserLookupServiceMock.lookupUserByCn("user!example.com") } answers {
            testLdapUser(memberOfCNs = listOf("some-other-group"))
        }
        Assert.assertThrows(DeltaSSOLoginController.OAuthLoginException::class.java) {
            runBlocking { testClient(loginState.cookie).get("/delta/oauth/test/callback?code=auth-code&state=${loginState.state}") }
        }.apply {
            assertEquals("not_delta_user", errorCode)
        }
    }

    @Test
    fun `Callback returns error if user is not in required Azure group`()  {
        coEvery {
            microsoftGraphServiceMock.checkCurrentUserGroups(accessToken, any())
        } answers { listOf() }
        Assert.assertThrows(DeltaSSOLoginController.OAuthLoginException::class.java) {
            runBlocking { testClient(loginState.cookie).get("/delta/oauth/test/callback?code=auth-code&state=${loginState.state}") }
        }.apply {
            assertEquals("not_in_required_azure_group", errorCode)
        }
    }

    private fun mockAdminUser() {
        every { ldapUserLookupServiceMock.lookupUserByCn("user!example.com") } answers {
            testLdapUser(memberOfCNs = listOf(deltaConfig.requiredGroupCn, "datamart-delta-admin"))
        }
    }

    @Test
    fun `Callback returns error if admin user is not in admin Azure group`() {
        mockAdminUser()
        Assert.assertThrows(DeltaSSOLoginController.OAuthLoginException::class.java) {
            runBlocking { testClient(loginState.cookie).get("/delta/oauth/test/callback?code=auth-code&state=${loginState.state}") }
        }.apply {
            assertEquals("not_in_required_admin_group", errorCode)
        }
    }

    @Test
    fun `Callback allows admin user`() = testSuspend {
        mockAdminUser()
        coEvery {
            microsoftGraphServiceMock.checkCurrentUserGroups(
                accessToken,
                listOf(ssoClient.requiredGroupId!!, ssoClient.requiredAdminGroupId!!)
            )
        } answers { listOf(ssoClient.requiredGroupId!!, ssoClient.requiredAdminGroupId!!) }
        testClient(loginState.cookie).get("/delta/oauth/test/callback?code=auth-code&state=${loginState.state}").apply {
            assertEquals(HttpStatusCode.Found, status)
            assertEquals(headers["Location"], "https://delta/redirect?code=code&state=delta-state")
        }
    }

    private fun testClient(cookie: Cookie? = null) = testApp.createClient {
        install(HttpCookies) {
            if (cookie != null) {
                default { storage.addCookie("/", cookie) }
            }
        }
        followRedirects = false
    }

    @Before
    fun setupMocks() {
        clearAllMocks()
        every { ldapUserLookupServiceMock.lookupUserByCn("user!example.com") } answers {
            testLdapUser(memberOfCNs = listOf(deltaConfig.requiredGroupCn))
        }
        every { authorizationCodeServiceMock.generateAndStore("cn", serviceClient, any()) } answers {
            AuthCode("code", "cn", serviceClient, Instant.MIN, "trace")
        }
        coEvery {
            microsoftGraphServiceMock.checkCurrentUserGroups(
                accessToken,
                listOf(ssoClient.requiredGroupId!!, ssoClient.requiredAdminGroupId!!)
            )
        } answers {
            listOf(ssoClient.requiredGroupId!!)
        }
    }

    private fun String.stateFromRedirectUrl() =
        Regex("state=([^&]+)[&$]").find(this)!!.groups[1]!!.value

    companion object {
        private lateinit var testApp: TestApplication
        private val deltaConfig = DeltaConfig.fromEnv()
        private val serviceClient = testServiceClient()
        private val ssoClient = AzureADSSOClient(
            "test",
            "tenant-id",
            "sso-client-id",
            "sso-client-secret",
            buttonText = "Test SSO",
            requiredGroupId = "required-group-id",
            requiredAdminGroupId = "required-admin-group-id",
        )
        private val ssoConfig = AzureADSSOConfig(listOf(ssoClient))
        private val ldapUserLookupServiceMock = mockk<UserLookupService>()
        private val authorizationCodeServiceMock = mockk<AuthorizationCodeService>()
        private val microsoftGraphServiceMock = mockk<MicrosoftGraphService>()
        private val ssoLoginStateService = SSOLoginSessionStateService()
        private val accessToken = "header.${"{\"unique_name\": \"user@example.com\"}".encodeBase64()}.trailer"

        @BeforeClass
        @JvmStatic
        fun setup() {
            val loginPageController = DeltaLoginController(
                listOf(serviceClient),
                ssoConfig,
                deltaConfig,
                mockk(),
                authorizationCodeServiceMock
            )
            val oauthController = DeltaSSOLoginController(
                deltaConfig,
                ClientConfig(listOf(serviceClient)),
                ssoConfig,
                ssoLoginStateService,
                ldapUserLookupServiceMock,
                authorizationCodeServiceMock,
                microsoftGraphServiceMock,
            )
            val oauthClientProviderLookupService = SSOOAuthClientProviderLookupService(
                ssoConfig, ssoLoginStateService
            )
            val mockHttpEngine = MockEngine {
                respond(
                    content = ByteReadChannel(
                        """{
                                "access_token": "header.${"{\"unique_name\": \"user@example.com\"}".encodeBase64()}.trailer",
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
                    azureAdSingleSignOn(
                        AuthServiceConfig("http://auth-service"),
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
