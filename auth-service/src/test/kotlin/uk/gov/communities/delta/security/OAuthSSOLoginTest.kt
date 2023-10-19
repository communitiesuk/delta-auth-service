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
import io.micrometer.core.instrument.Metrics.counter
import io.mockk.*
import kotlinx.coroutines.runBlocking
import org.junit.*
import org.junit.runner.RunWith
import org.junit.runners.BlockJUnit4ClassRunner
import uk.gov.communities.delta.auth.config.*
import uk.gov.communities.delta.auth.controllers.external.DeltaLoginController
import uk.gov.communities.delta.auth.controllers.external.DeltaSSOLoginController
import uk.gov.communities.delta.auth.deltaLoginRoutes
import uk.gov.communities.delta.auth.plugins.configureTemplating
import uk.gov.communities.delta.auth.security.azureAdSingleSignOn
import uk.gov.communities.delta.auth.security.configureRateLimiting
import uk.gov.communities.delta.auth.services.*
import uk.gov.communities.delta.auth.services.sso.MicrosoftGraphService
import uk.gov.communities.delta.auth.services.sso.SSOLoginSessionStateService
import uk.gov.communities.delta.auth.services.sso.SSOOAuthClientProviderLookupService
import uk.gov.communities.delta.helper.testLdapUser
import uk.gov.communities.delta.helper.testServiceClient
import java.time.Instant
import javax.naming.NameNotFoundException
import kotlin.test.assertContains
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue


@RunWith(SingleInstanceRunner::class)
class OAuthSSOLoginTest {

    @Test
    fun testOAuthFlow() = testSuspend {
        // OAuth flow happy path
        val testClient = testClient()

        // Get the login page (required as it sets a cookie with the Delta client id and state in)
        testClient.get("/delta/login?response_type=code&client_id=delta-website&state=delta-state").apply {
            assertEquals(HttpStatusCode.OK, status)
            assertContains(bodyAsText(), "Test SSO</a>")
        }

        // Request to the OAuth login endpoint as though we'd pressed the SSO button
        val oauthLoginResponse = testClient.get("/delta/oauth/test/login").apply {
            assertEquals(HttpStatusCode.Found, status)
        }
        // Expect a redirect to Microsoft's Authorize endpoint
        val externalServiceRedirect = oauthLoginResponse.headers["Location"]
        assertNotNull(externalServiceRedirect, "Location header expected")
        assertTrue(externalServiceRedirect.startsWith("https://login.microsoftonline.com/${ssoClient.azTenantId}/oauth2/v2.0/authorize"))
        assertContains(externalServiceRedirect, "client_id=${ssoClient.azClientId}")
        assertContains(
            externalServiceRedirect,
            "redirect_uri=${"http://auth-service/delta/oauth/test/callback".encodeURLParameter()}"
        )
        val state = externalServiceRedirect.stateFromRedirectUrl()

        // Microsoft would then redirect the user back to the redirect ("callback") endpoint
        testClient.get("/delta/oauth/test/callback?code=auth-code&state=${state}").apply {
            // Which should redirect us back to Delta with an Authorisation code
            assertEquals(HttpStatusCode.Found, status)
            assertEquals("https://delta/login/oauth2/redirect?code=code&state=delta-state", headers["Location"])
            coVerify { authorizationCodeServiceMock.generateAndStore("cn", serviceClient, any()) }
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

    @Test
    fun `Callback endpoint throws error with no session cookie`() {
        Assert.assertThrows(DeltaSSOLoginController.OAuthLoginException::class.java) {
            runBlocking { testClient().get("/delta/oauth/test/callback") }
        }.apply {
            assertEquals("callback_no_session", errorCode)
        }
    }

    private class LoginState(val cookie: Cookie, val state: String)

    // Cookie and state parameter as though the user had just been redirected to Azure
    // shared between tests to avoid repeating the requests
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
                assertTrue(headers["Location"]!!.startsWith("${deltaConfig.deltaWebsiteUrl}/login?error=delta_sso_failed&sso_error=some_azure_error"))
                coVerify(exactly = 0) { authorizationCodeServiceMock.generateAndStore("cn", serviceClient, any()) }
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
    fun `Callback redirects to register page if no ldap user for non-required SSO client`() = testSuspend {
        val userCN = "user!example.com"
        coEvery { ldapUserLookupServiceMock.lookupUserByCn(userCN) } throws (NameNotFoundException()) andThen testLdapUser(
            memberOfCNs = listOf(deltaConfig.datamartDeltaUser)
        )
        val organisations = listOf(Organisation("E1234", "Test Organisation"))
        coEvery { organisationService.findAllByDomain("example.com") } returns organisations
        coEvery { registrationService.register(any(), any(), true) } returns RegistrationService.SSOUserCreated

        testClient(loginState.cookie).get("/delta/oauth/test/callback?code=auth-code&state=${loginState.state}")
            .apply {
                val registration = Registration("Example", "User", "user@example.com")
                coVerify(exactly = 0) { registrationService.register(registration, organisations, true) }
                assertEquals(HttpStatusCode.Found, status)
                assertEquals("/delta/register", headers["Location"])
            }
    }

    @Test
    fun `Callback calls register function if no ldap user for required SSO client`() = testSuspend {
        every { ssoConfig.ssoClients } answers { listOf(ssoClient.copy(required = true)) }
        val userCN = "user!example.com"
        coEvery { ldapUserLookupServiceMock.lookupUserByCn(userCN) } throws (NameNotFoundException()) andThen testLdapUser(
            memberOfCNs = listOf(deltaConfig.datamartDeltaUser)
        )
        val organisations = listOf(Organisation("E1234", "Test Organisation"))
        coEvery { organisationService.findAllByDomain("example.com") } returns organisations
        coEvery { registrationService.register(any(), any(), true) } returns RegistrationService.SSOUserCreated

        testClient(loginState.cookie).get("/delta/oauth/test/callback?code=auth-code&state=${loginState.state}")
            .apply {
                val registration = Registration("Example", "User", "user@example.com")
                coVerify(exactly = 1) { registrationService.register(registration, organisations, true) }
                assertEquals(HttpStatusCode.Found, status)
                assertEquals("https://delta/login/oauth2/redirect?code=code&state=delta-state", headers["Location"])
            }
    }

    @Test
    fun `Callback returns error if user is disabled`() {
        coEvery { ldapUserLookupServiceMock.lookupUserByCn("user!example.com") } answers {
            testLdapUser(memberOfCNs = listOf(deltaConfig.datamartDeltaUser), accountEnabled = false)
        }
        Assert.assertThrows(DeltaSSOLoginController.OAuthLoginException::class.java) {
            runBlocking { testClient(loginState.cookie).get("/delta/oauth/test/callback?code=auth-code&state=${loginState.state}") }
        }.apply {
            assertEquals("user_disabled", errorCode)
        }
    }

    @Test
    fun `Callback returns error if user has no email`() {
        coEvery { ldapUserLookupServiceMock.lookupUserByCn("user!example.com") } answers {
            testLdapUser(memberOfCNs = listOf(deltaConfig.datamartDeltaUser), email = null)
        }
        Assert.assertThrows(DeltaSSOLoginController.OAuthLoginException::class.java) {
            runBlocking { testClient(loginState.cookie).get("/delta/oauth/test/callback?code=auth-code&state=${loginState.state}") }
        }.apply {
            assertEquals("user_no_mail_attribute", errorCode)
        }
    }

    @Test
    fun `Callback returns error if user is not in Delta users group`() {
        coEvery { ldapUserLookupServiceMock.lookupUserByCn("user!example.com") } answers {
            testLdapUser(memberOfCNs = listOf("some-other-group"))
        }
        Assert.assertThrows(DeltaSSOLoginController.OAuthLoginException::class.java) {
            runBlocking { testClient(loginState.cookie).get("/delta/oauth/test/callback?code=auth-code&state=${loginState.state}") }
        }.apply {
            assertEquals("not_delta_user", errorCode)
        }
    }

    @Test
    fun `Callback returns error if user is not in required Azure group`() {
        coEvery { microsoftGraphServiceMock.checkCurrentUserGroups(accessToken, any()) } answers { listOf() }

        Assert.assertThrows(DeltaSSOLoginController.OAuthLoginException::class.java) {
            runBlocking { testClient(loginState.cookie).get("/delta/oauth/test/callback?code=auth-code&state=${loginState.state}") }
        }.apply {
            assertEquals("not_in_required_azure_group", errorCode)
        }
    }

    @Test
    fun `Callback returns error if email doesn't match domain`() {
        every { ssoConfig.ssoClients } answers { listOf(ssoClient.copy(emailDomain = "@different.domain")) }
        Assert.assertThrows(DeltaSSOLoginController.OAuthLoginException::class.java) {
            runBlocking { testClient(loginState.cookie).get("/delta/oauth/test/callback?code=auth-code&state=${loginState.state}") }
        }.apply {
            assertEquals("invalid_email_domain", errorCode)
        }
    }

    private fun mockAdminUser() {
        coEvery { ldapUserLookupServiceMock.lookupUserByCn("user!example.com") } answers {
            testLdapUser(memberOfCNs = listOf(deltaConfig.datamartDeltaUser, "datamart-delta-admin"))
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
            assertEquals(headers["Location"], "https://delta/login/oauth2/redirect?code=code&state=delta-state")
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
        coEvery { ldapUserLookupServiceMock.lookupUserByCn("user!example.com") } answers {
            testLdapUser(memberOfCNs = listOf(deltaConfig.datamartDeltaUser))
        }
        coEvery { authorizationCodeServiceMock.generateAndStore("cn", serviceClient, any()) } answers {
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
        every { ssoConfig.ssoClients } answers { listOf(ssoClient) }
    }

    private fun String.stateFromRedirectUrl() =
        Regex("state=([^&]+)[&$]").find(this)!!.groups[1]!!.value

    companion object {
        private lateinit var testApp: TestApplication
        private val deltaConfig = DeltaConfig.fromEnv()
        private val serviceConfig = AuthServiceConfig("testServiceUrl", null)
        private val serviceClient = testServiceClient()
        private val ssoClient = AzureADSSOClient(
            "test",
            "tenant-id",
            "sso-client-id",
            "sso-client-secret",
            "@example.com",
            buttonText = "Test SSO",
            requiredGroupId = "required-group-id",
            requiredAdminGroupId = "required-admin-group-id",
        )
        private val ssoConfig = mockk<AzureADSSOConfig>()
        private val accessToken =
            "header.${"{\"unique_name\": \"user@example.com\", \"given_name\": \"Example\", \"family_name\": \"User\"}".encodeBase64()}.trailer"
        private lateinit var ldapUserLookupServiceMock: UserLookupService
        private lateinit var authorizationCodeServiceMock: AuthorizationCodeService
        private lateinit var microsoftGraphServiceMock: MicrosoftGraphService
        private lateinit var ssoLoginStateService: SSOLoginSessionStateService
        private lateinit var registrationService: RegistrationService
        private lateinit var organisationService: OrganisationService

        @BeforeClass
        @JvmStatic
        fun setup() {
            ssoLoginStateService = SSOLoginSessionStateService()
            microsoftGraphServiceMock = mockk<MicrosoftGraphService>()
            authorizationCodeServiceMock = mockk<AuthorizationCodeService>()
            ldapUserLookupServiceMock = mockk<UserLookupService>()
            registrationService = mockk<RegistrationService>()
            organisationService = mockk<OrganisationService>()
            val loginPageController = DeltaLoginController(
                listOf(serviceClient),
                ssoConfig,
                deltaConfig,
                mockk(),
                authorizationCodeServiceMock,
                counter("failedLoginNoopCounter"),
                counter("successfulLoginNoopCounter")
            )
            val oauthController = DeltaSSOLoginController(
                deltaConfig,
                ClientConfig(listOf(serviceClient)),
                ssoConfig,
                ssoLoginStateService,
                ldapUserLookupServiceMock,
                authorizationCodeServiceMock,
                microsoftGraphServiceMock,
                registrationService,
                organisationService,
            )
            val oauthClientProviderLookupService = SSOOAuthClientProviderLookupService(
                ssoConfig, ssoLoginStateService
            )
            val mockOAuthTokenRequestHttpEngine = MockEngine {
                respond(
                    content = ByteReadChannel(
                        """{
                                "access_token": $accessToken,
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
                        AuthServiceConfig("http://auth-service", null),
                        HttpClient(mockOAuthTokenRequestHttpEngine),
                        oauthClientProviderLookupService,
                    )
                }
                application {
                    configureTemplating(false)
                    configureRateLimiting(
                        10,
                        counter("loginRateLimitingNoopCounter"),
                        counter("registrationRateLimitingNoopCounter"),
                        counter("setPasswordRateLimitingNoopCounter"),
                        counter("resetPasswordRateLimitingNoopCounter"),
                        counter("forgotPasswordRateLimitingNoopCounter"),
                    )
                    routing {
                        route("/delta") {
                            deltaLoginRoutes(serviceConfig, loginPageController, oauthController)
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

class SingleInstanceRunner<T>(clazz: Class<T>) : BlockJUnit4ClassRunner(clazz) {
    private val instance: Any by lazy { super.createTest() }

    override fun createTest() = instance
}
