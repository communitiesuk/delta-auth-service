package uk.gov.communities.delta.controllers

import io.ktor.client.request.*
import io.ktor.client.request.forms.*
import io.ktor.client.statement.*
import io.ktor.http.*
import io.ktor.server.application.*
import io.ktor.server.routing.*
import io.ktor.server.testing.*
import io.ktor.test.dispatcher.*
import org.junit.AfterClass
import org.junit.BeforeClass
import org.junit.Test
import uk.gov.communities.delta.auth.config.Client
import uk.gov.communities.delta.auth.config.DeltaConfig
import uk.gov.communities.delta.auth.controllers.external.DeltaLoginController
import uk.gov.communities.delta.auth.plugins.configureTemplating
import uk.gov.communities.delta.auth.security.IADLdapLoginService
import uk.gov.communities.delta.auth.services.AuthCode
import uk.gov.communities.delta.auth.services.IAuthorizationCodeService
import uk.gov.communities.delta.auth.services.LdapUser
import kotlin.test.assertContains
import kotlin.test.assertEquals


class DeltaLoginControllerTest {

    @Test
    fun testLoginPage() = testSuspend {
        testApp.client.get("/login?response_type=code&client_id=delta-website&state=1234").apply {
            assertEquals(HttpStatusCode.OK, status)
            assertContains(bodyAsText(), "Sign in to DELTA")
        }
    }

    @Test
    fun testLoginPostAccountDisabled() = testSuspend {
        loginResult = IADLdapLoginService.DisabledAccount
        testApp.client.submitForm(
            url = "/login?response_type=code&client_id=delta-website&state=1234",
            formParameters = parameters {
                append("username", "user")
                append("password", "pass")
            }
        ).apply {
            assertEquals(HttpStatusCode.OK, status)
            assertContains(bodyAsText(), "Your account has been disabled")
        }
    }

    @Test
    fun testLoginPostNotInGroup() = testSuspend {
        loginResult = IADLdapLoginService.LdapLoginSuccess(LdapUser("username", listOf()))
        testApp.client.submitForm(
            url = "/login?response_type=code&client_id=delta-website&state=1234",
            formParameters = parameters {
                append("username", "user")
                append("password", "pass")
            }
        ).apply {
            assertEquals(HttpStatusCode.OK, status)
            assertContains(bodyAsText(), "Your account exists but is not set up to access Delta.")
        }
    }

    @Test
    fun testLoginPostSuccess() = testSuspend {
        loginResult = IADLdapLoginService.LdapLoginSuccess(LdapUser("username", listOf(DeltaConfig.fromEnv().requiredGroupCn)))
        testApp.client.submitForm(
            url = "/login?response_type=code&client_id=delta-website&state=1234",
            formParameters = parameters {
                append("username", "user")
                append("password", "pass")
            }
        ).apply {
            // TODO DT-525 Clearly not the final behaviour!
            assertEquals(HttpStatusCode.Found, status)
//            assertEquals(bodyAsText(), "Successful login user")
        }
    }

    companion object {
        private lateinit var testApp: TestApplication
        private lateinit var loginResult: IADLdapLoginService.LdapLoginResult

        @BeforeClass
        @JvmStatic
        fun setup() {
            val controller = DeltaLoginController(
                Client("delta-website", "client-secret"),
                DeltaConfig.fromEnv(),
                object : IADLdapLoginService {
                    override fun ldapLogin(username: String, password: String): IADLdapLoginService.LdapLoginResult {
                        return loginResult
                    }
                },
                object : IAuthorizationCodeService {
                    override fun generateAndStore(userCn: String): String {
                        return "test-auth-code"
                    }

                    override fun lookupAndInvalidate(code: String): AuthCode? {
                        throw NotImplementedError("Not required for test")
                    }
                }
            )
            testApp = TestApplication {
                application {
                    configureTemplating(false)
                    routing {
                        route("/login") {
                            get { controller.loginGet(call) }
                            post { controller.loginPost(call) }
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
