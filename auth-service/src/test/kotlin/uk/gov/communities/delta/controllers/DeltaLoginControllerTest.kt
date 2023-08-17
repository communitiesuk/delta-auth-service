package uk.gov.communities.delta.controllers

import io.ktor.client.*
import io.ktor.client.request.*
import io.ktor.client.request.forms.*
import io.ktor.client.statement.*
import io.ktor.http.*
import io.ktor.server.plugins.callid.*
import io.ktor.server.routing.*
import io.ktor.server.sessions.*
import io.ktor.server.testing.*
import io.ktor.test.dispatcher.*
import io.micrometer.core.instrument.Counter
import io.mockk.*
import org.junit.AfterClass
import org.junit.Before
import org.junit.BeforeClass
import org.junit.Test
import uk.gov.communities.delta.auth.LoginSessionCookie
import uk.gov.communities.delta.auth.config.*
import uk.gov.communities.delta.auth.controllers.external.DeltaLoginController
import uk.gov.communities.delta.auth.oauthClientLoginRoute
import uk.gov.communities.delta.auth.plugins.configureTemplating
import uk.gov.communities.delta.auth.security.IADLdapLoginService
import uk.gov.communities.delta.auth.services.AuthCode
import uk.gov.communities.delta.auth.services.IAuthorizationCodeService
import uk.gov.communities.delta.helper.testLdapUser
import uk.gov.communities.delta.helper.testServiceClient
import java.time.Instant
import kotlin.test.assertContains
import kotlin.test.assertEquals
import kotlin.test.assertTrue


class DeltaLoginControllerTest {

    @Test
    fun testLoginPage() = testSuspend {
        testClient.get("/login?response_type=code&client_id=delta-website&state=1234").apply {
            assertEquals(HttpStatusCode.OK, status)
            assertContains(bodyAsText(), "Sign in to DELTA")
        }
    }

    @Test
    fun testLoginInvalidParamsRedirectsToDelta() = testSuspend {
        testClient.get("/login").apply {
            assertEquals(HttpStatusCode.Found, status)
            headers["Location"]!!.startsWith(deltaConfig.deltaWebsiteUrl + "/login?error=delta_invalid_params")
        }
    }

    @Test
    fun testLoginPostAccountDisabled() = testSuspend {
        loginResult = IADLdapLoginService.DisabledAccount
        testClient.submitForm(
            url = "/login?response_type=code&client_id=delta-website&state=1234",
            formParameters = parameters {
                append("username", "user")
                append("password", "pass")
            }
        ).apply {
            assertEquals(HttpStatusCode.OK, status)
            assertContains(bodyAsText(), "Your account has been disabled")
            verify(exactly=1) { failedLoginCounter.increment(1.0) }
            verify(exactly=0) { successfulLoginCounter.increment(1.0) }
        }
    }

    @Test
    fun testLoginPostNotInGroup() = testSuspend {
        loginResult = IADLdapLoginService.LdapLoginSuccess(
            testLdapUser(cn = "username", memberOfCNs = listOf("some-other-group"))
        )
        testClient.submitForm(
            url = "/login?response_type=code&client_id=delta-website&state=1234",
            formParameters = parameters {
                append("username", "user")
                append("password", "pass")
            }
        ).apply {
            assertEquals(HttpStatusCode.OK, status)
            assertContains(bodyAsText(), "Your account exists but is not set up to access Delta.")
            verify(exactly=1) { failedLoginCounter.increment(1.0) }
            verify(exactly=0) { successfulLoginCounter.increment(1.0) }
        }
    }

    @Test
    fun testLoginPostNoEmail() = testSuspend {
        loginResult = IADLdapLoginService.LdapLoginSuccess(
            testLdapUser(cn = "username", memberOfCNs = listOf(deltaConfig.requiredGroupCn), email = null)
        )
        testClient.submitForm(
            url = "/login?response_type=code&client_id=delta-website&state=1234",
            formParameters = parameters {
                append("username", "user")
                append("password", "pass")
            }
        ).apply {
            assertEquals(HttpStatusCode.OK, status)
            assertContains(bodyAsText(), "Your account exists but is not fully set up (missing mail attribute). Please contact the Service Desk.")
            verify(exactly=1) { failedLoginCounter.increment(1.0) }
            verify(exactly=0) { successfulLoginCounter.increment(1.0) }
        }
    }

    @Test
    fun testLoginPostSuccess() = testSuspend {
        loginResult = IADLdapLoginService.LdapLoginSuccess(
            testLdapUser(cn = "username", memberOfCNs = listOf(deltaConfig.requiredGroupCn))
        )
        testClient.submitForm(
            url = "/login?response_type=code&client_id=delta-website&state=1234",
            formParameters = parameters {
                append("username", "user")
                append("password", "pass")
            }
        ).apply {
            assertEquals(HttpStatusCode.Found, status)
            assertTrue("Should redirect to Delta website") {
                headers["Location"]!!.startsWith(client.deltaWebsiteUrl + "/login/oauth2/redirect")
            }
            verify(exactly=0) { failedLoginCounter.increment(1.0) }
            verify(exactly=1) { successfulLoginCounter.increment(1.0) }
        }
    }

    @Test
    fun testLoginPostSSODomainRedirects() = testSuspend {
        testClient.submitForm(
            url = "/login?response_type=code&client_id=delta-website&state=1234",
            formParameters = parameters {
                append("username", "user@sso.domain")
                append("password", "pass")
            }
        ).apply {
            assertEquals(HttpStatusCode.Found, status)
            assertEquals(oauthClientLoginRoute("dev"), headers["Location"], "Should redirect to OAuth route")
            verify(exactly=0) { failedLoginCounter.increment(1.0) }
            verify(exactly=0) { successfulLoginCounter.increment(1.0) }
        }
    }

    @Before
    fun resetCounters() {
        clearAllMocks()
        every { failedLoginCounter.increment(1.0) } returns Unit
        every { successfulLoginCounter.increment(1.0) } returns Unit
    }

    companion object {
        private lateinit var testApp: TestApplication
        private lateinit var testClient: HttpClient
        private lateinit var loginResult: IADLdapLoginService.LdapLoginResult
        private val deltaConfig = DeltaConfig.fromEnv()
        val client = testServiceClient()
        val failedLoginCounter = mockk<Counter>()
        val successfulLoginCounter = mockk<Counter>()

        @BeforeClass
        @JvmStatic
        fun setup() {
            val controller = DeltaLoginController(
                listOf(client),
                AzureADSSOConfig(listOf(AzureADSSOClient("dev", "", "", "", "@sso.domain"))),
                deltaConfig,
                object : IADLdapLoginService {
                    override fun ldapLogin(username: String, password: String): IADLdapLoginService.LdapLoginResult {
                        return loginResult
                    }
                },
                object : IAuthorizationCodeService {
                    override fun generateAndStore(userCn: String, client: Client, traceId: String): AuthCode {
                        return AuthCode("test-auth-code", "user", client, Instant.now(), "trace")
                    }

                    override fun lookupAndInvalidate(code: String, client: Client): AuthCode? {
                        throw NotImplementedError("Not required for test")
                    }
                },
                failedLoginCounter,
                successfulLoginCounter
            )
            testApp = TestApplication {
                install(CallId) { generate(4) }
                install(Sessions) {
                    cookie<LoginSessionCookie>("LOGIN_SESSION")
                }
                application {
                    configureTemplating(false)
                    routing {
                        route("/login") {
                            controller.loginRoutes(this)
                        }
                    }
                }
            }
            testClient = testApp.createClient { followRedirects = false }
        }

        @AfterClass
        @JvmStatic
        fun tearDown() {
            testApp.stop()
        }
    }
}
