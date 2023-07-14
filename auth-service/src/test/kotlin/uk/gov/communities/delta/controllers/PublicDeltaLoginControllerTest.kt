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
import uk.gov.communities.delta.auth.config.DeltaConfig
import uk.gov.communities.delta.auth.controllers.PublicDeltaLoginController
import uk.gov.communities.delta.auth.plugins.configureTemplating
import uk.gov.communities.delta.auth.security.ADLdapLoginService
import uk.gov.communities.delta.auth.security.LdapUser
import kotlin.test.assertContains
import kotlin.test.assertEquals


class PublicDeltaLoginControllerTest {

    @Test
    fun testLoginPage() = testSuspend {
        testApp.client.get("/login").apply {
            assertEquals(HttpStatusCode.OK, status)
            assertContains(bodyAsText(), "Sign in to DELTA")
        }
    }

    @Test
    fun testLoginPostAccountDisabled() = testSuspend {
        loginResult = ADLdapLoginService.DisabledAccount
        testApp.client.submitForm(
            url = "/login",
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
        loginResult = ADLdapLoginService.LdapLoginSuccess(LdapUser("username", listOf()))
        testApp.client.submitForm(
            url = "/login",
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
        loginResult = ADLdapLoginService.LdapLoginSuccess(LdapUser("username", listOf(DeltaConfig.REQUIRED_GROUP_CN)))
        testApp.client.submitForm(
            url = "/login",
            formParameters = parameters {
                append("username", "user")
                append("password", "pass")
            }
        ).apply {
            // TODO DT-525 Clearly not the final behaviour!
            assertEquals(HttpStatusCode.OK, status)
            assertEquals(bodyAsText(), "Successful login user")
        }
    }

    companion object {
        private lateinit var testApp: TestApplication
        private lateinit var loginResult: ADLdapLoginService.LdapLoginResult

        @BeforeClass
        @JvmStatic
        fun setup() {
            val controller = PublicDeltaLoginController(object : ADLdapLoginService {
                override fun ldapLogin(username: String, password: String): ADLdapLoginService.LdapLoginResult {
                    return loginResult
                }

            })
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
