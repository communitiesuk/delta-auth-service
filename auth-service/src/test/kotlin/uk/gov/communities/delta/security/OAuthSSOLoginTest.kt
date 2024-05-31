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
import io.micrometer.core.instrument.Counter
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
            coVerify(exactly = 1) {
                authorizationCodeServiceMock.generateAndStore(testUser.getGUID(), serviceClient, any(), true)
            }
            verify(exactly = 1) { ssoLoginCounter.increment() }
            coVerify(exactly = 1) {
                userAuditService.userSSOLoginAudit(testUser.getGUID(), ssoClient, "abc-123", any())
            }
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
                coVerify(exactly = 0) {
                    authorizationCodeServiceMock.generateAndStore(testUser.getGUID(), serviceClient, any(), true)
                }
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
        coEvery { userGUIDMapService.userGUIDIfExists(testUser.email!!) } returns null andThen testUser.getGUID()
        val organisations = listOf(Organisation("E1234", "Test Organisation"))
        coEvery { organisationService.findAllByDomain("example.com") } returns organisations
        coEvery {
            registrationService.register(any<Registration>(), any(), any(), ssoClient)
        } returns RegistrationService.SSOUserCreated

        testClient(loginState.cookie).get("/delta/oauth/test/callback?code=auth-code&state=${loginState.state}")
            .apply {
                val registration = Registration(testUser.firstName, testUser.lastName, testUser.email!!)
                coVerify(exactly = 0) { registrationService.register(registration, organisations, any(), ssoClient) }
                assertEquals(HttpStatusCode.Found, status)
                assertEquals("/delta/register?fromSSOEmail=user%40example.com", headers["Location"])
            }
    }

    @Test
    fun `Callback calls register function if no ldap user for required SSO client`() = testSuspend {
        val requiredSsoClient = ssoClient.copy(required = true)
        every { ssoConfig.ssoClients } answers { listOf(requiredSsoClient) }
        coEvery { userGUIDMapService.userGUIDIfExists(testUser.email!!) } returns null andThen testUser.getGUID()
        val organisations = listOf(Organisation("E1234", "Test Organisation"))
        coEvery { organisationService.findAllByDomain("example.com") } returns organisations
        coEvery {
            registrationService.register(any<Registration>(), any(), any(), requiredSsoClient)
        } returns RegistrationService.SSOUserCreated

        testClient(loginState.cookie).get("/delta/oauth/test/callback?code=auth-code&state=${loginState.state}")
            .apply {
                val registration = Registration(testUser.firstName, testUser.lastName, testUser.email!!, "abc-123")
                coVerify(exactly = 1) {
                    registrationService.register(registration, organisations, any(), requiredSsoClient)
                }
                assertEquals(HttpStatusCode.Found, status)
                assertEquals("https://delta/login/oauth2/redirect?code=code&state=delta-state", headers["Location"])
            }
    }

    @Test
    fun `Callback returns error if user is disabled`() {
        val disabledUser = testLdapUser(
            email = tokenEmail,
            memberOfCNs = listOf(DeltaConfig.DATAMART_DELTA_USER),
            accountEnabled = false
        )
        coEvery { userGUIDMapService.userGUIDIfExists(disabledUser.email!!) } returns disabledUser.getGUID()
        coEvery { ldapUserLookupServiceMock.lookupUserByGUID(disabledUser.getGUID()) } returns disabledUser
        Assert.assertThrows(DeltaSSOLoginController.OAuthLoginException::class.java) {
            runBlocking { testClient(loginState.cookie).get("/delta/oauth/test/callback?code=auth-code&state=${loginState.state}") }
        }.apply {
            assertEquals("user_disabled", errorCode)
        }
    }

    @Test
    fun `Callback returns error if user has no email`() {
        val noEmailUser = testLdapUser(memberOfCNs = listOf(DeltaConfig.DATAMART_DELTA_USER), email = null)
        coEvery { userGUIDMapService.userGUIDIfExists(tokenEmail) } returns noEmailUser.getGUID()
        coEvery { ldapUserLookupServiceMock.lookupUserByGUID(noEmailUser.getGUID()) } returns noEmailUser
        Assert.assertThrows(DeltaSSOLoginController.OAuthLoginException::class.java) {
            runBlocking { testClient(loginState.cookie).get("/delta/oauth/test/callback?code=auth-code&state=${loginState.state}") }
        }.apply {
            assertEquals("user_no_mail_attribute", errorCode)
        }
    }

    @Test
    fun `Callback returns error if user is not in Delta users group`() {
        val userNotInUserGroup = testLdapUser(memberOfCNs = listOf("some-other-group"))
        coEvery { userGUIDMapService.userGUIDIfExists(tokenEmail) } returns userNotInUserGroup.getGUID()
        coEvery { ldapUserLookupServiceMock.lookupUserByGUID(userNotInUserGroup.getGUID()) } returns userNotInUserGroup
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
        val adminUser =
            testLdapUser(
                email = tokenEmail,
                memberOfCNs = listOf(DeltaConfig.DATAMART_DELTA_USER, DeltaConfig.DATAMART_DELTA_ADMIN)
            )
        coEvery { userGUIDMapService.userGUIDIfExists(adminUser.email!!) } returns adminUser.getGUID()
        coEvery { ldapUserLookupServiceMock.lookupUserByGUID(adminUser.getGUID()) } returns adminUser
        coEvery {
            authorizationCodeServiceMock.generateAndStore(adminUser.getGUID(), serviceClient, any(), true)
        } answers {
            AuthCode("code", adminUser.getGUID(), serviceClient, Instant.MIN, "trace", true)
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

    @Test
    fun `Callback maps email domain from jwt`() = testSuspend {
        coEvery {
            microsoftGraphServiceMock.checkCurrentUserGroups(
                emailMappingAccessToken,
                listOf(emailMappingSSOClient.requiredGroupId!!, emailMappingSSOClient.requiredAdminGroupId!!)
            )
        } answers { listOf(emailMappingSSOClient.requiredGroupId!!) }
        coEvery {
            authorizationCodeServiceMock.generateAndStore(domainUser.getGUID(), serviceClient, any(), true)
        } answers { AuthCode("code", domainUser.getGUID(), serviceClient, Instant.MIN, "trace", true) }

        val loginState = runBlocking {
            val client = testClient()
            client.get("/delta/login?response_type=code&client_id=delta-website&state=delta-state")
            val state = client.get("/delta/oauth/mapping-test/login").headers["Location"]!!.stateFromRedirectUrl()
            val cookie = client.cookies("http://localhost/")[0]
            LoginState(cookie, state)
        }
        testClient(loginState.cookie).get("/delta/oauth/mapping-test/callback?code=auth-code&state=${loginState.state}")
            .apply {
                assertEquals(HttpStatusCode.Found, status)
                assertEquals(headers["Location"], "https://delta/login/oauth2/redirect?code=code&state=delta-state")
                coVerify(exactly = 1) {
                    authorizationCodeServiceMock.generateAndStore(domainUser.getGUID(), serviceClient, any(), true)
                }
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
        coEvery { userGUIDMapService.userGUIDIfExists(testUser.email!!) } returns testUser.getGUID()
        coEvery { userGUIDMapService.userGUIDIfExists(domainUser.email!!) } returns domainUser.getGUID()
        coEvery { ldapUserLookupServiceMock.lookupUserByGUID(testUser.getGUID()) } returns testUser
        coEvery { ldapUserLookupServiceMock.lookupUserByGUID(domainUser.getGUID()) } returns domainUser
        coEvery {
            authorizationCodeServiceMock.generateAndStore(testUser.getGUID(), serviceClient, any(), true)
        } answers { AuthCode("code", testUser.getGUID(), serviceClient, Instant.MIN, "trace", true) }
        coEvery {
            microsoftGraphServiceMock.checkCurrentUserGroups(
                accessToken,
                listOf(ssoClient.requiredGroupId!!, ssoClient.requiredAdminGroupId!!)
            )
        } answers {
            listOf(ssoClient.requiredGroupId!!)
        }
        every { ssoConfig.ssoClients } answers { listOf(ssoClient, emailMappingSSOClient) }
        coEvery { userAuditService.userSSOLoginAudit(any(), any(), any(), any()) } returns Unit
        every { ssoLoginCounter.increment() } just runs
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
        private val emailMappingSSOClient = AzureADSSOClient(
            "mapping-test",
            "mapping-tenant-id",
            "mapping-sso-client-id",
            "mapping-sso-client-secret",
            "@email-domain.com",
            convertFromEmailDomain = "@azure-domain.com",
            buttonText = "Test SSO",
            requiredGroupId = "required-group-id",
            requiredAdminGroupId = "required-admin-group-id",
        )
        private val ssoConfig = mockk<AzureADSSOConfig>()
        private const val tokenEmail = "user@example.com"
        private val accessToken =
            "header.${"{\"unique_name\": \"$tokenEmail\", \"given_name\": \"Example\", \"family_name\": \"User\", \"oid\": \"abc-123\"}".encodeBase64()}.trailer"
        private val emailMappingAccessToken =
            "header.${"{\"unique_name\": \"user@azure-domain.com\", \"given_name\": \"Example\", \"family_name\": \"User\", \"oid\": \"abc-321\"}".encodeBase64()}.trailer"
        private val testUser = testLdapUser(
            cn = "user!example.com",
            email = tokenEmail,
            firstName = "Example",
            lastName = "User",
            memberOfCNs = listOf(DeltaConfig.DATAMART_DELTA_USER)
        )
        private val domainUser = testLdapUser(
            cn = "user!email-domain.com",
            email = "user@email-domain.com",
            memberOfCNs = listOf(DeltaConfig.DATAMART_DELTA_USER)
        )
        private lateinit var ldapUserLookupServiceMock: UserLookupService
        private lateinit var userGUIDMapService: UserGUIDMapService
        private lateinit var authorizationCodeServiceMock: AuthorizationCodeService
        private lateinit var microsoftGraphServiceMock: MicrosoftGraphService
        private lateinit var ssoLoginStateService: SSOLoginSessionStateService
        private lateinit var registrationService: RegistrationService
        private lateinit var organisationService: OrganisationService
        private lateinit var userAuditService: UserAuditService
        private lateinit var ssoLoginCounter: Counter

        @BeforeClass
        @JvmStatic
        fun setup() {
            ssoLoginStateService = SSOLoginSessionStateService()
            microsoftGraphServiceMock = mockk<MicrosoftGraphService>()
            authorizationCodeServiceMock = mockk<AuthorizationCodeService>()
            ldapUserLookupServiceMock = mockk<UserLookupService>()
            userGUIDMapService = mockk<UserGUIDMapService>()
            registrationService = mockk<RegistrationService>()
            organisationService = mockk<OrganisationService>()
            userAuditService = mockk<UserAuditService>()
            ssoLoginCounter = mockk<Counter>()
            val loginPageController = DeltaLoginController(
                listOf(serviceClient),
                ssoConfig,
                deltaConfig,
                mockk(),
                authorizationCodeServiceMock,
                counter("failedLoginNoopCounter"),
                counter("successfulLoginNoopCounter"),
                userAuditService
            )
            val oauthController = DeltaSSOLoginController(
                deltaConfig,
                ClientConfig(listOf(serviceClient)),
                ssoConfig,
                ssoLoginStateService,
                ldapUserLookupServiceMock,
                userGUIDMapService,
                authorizationCodeServiceMock,
                microsoftGraphServiceMock,
                registrationService,
                organisationService,
                ssoLoginCounter,
                userAuditService,
            )
            val oauthClientProviderLookupService = SSOOAuthClientProviderLookupService(
                ssoConfig, ssoLoginStateService
            )
            val mockOAuthTokenRequestHttpEngine = MockEngine.create {
                addHandler { request ->
                    respond(
                        content = ByteReadChannel(
                            """{
                                "access_token": ${
                                if (request.url.toString()
                                        .contains(emailMappingSSOClient.azTenantId)
                                ) emailMappingAccessToken else accessToken
                            },
                                "token_type": "Bearer",
                                "expires_in": 3599,
                                "scope": "Some.Scope"
                            }"""
                        ),
                        status = HttpStatusCode.OK,
                        headers = headersOf(HttpHeaders.ContentType, "application/json")
                    )
                }
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
