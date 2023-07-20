package uk.gov.communities.delta.security

import io.ktor.client.request.*
import io.ktor.client.statement.*
import io.ktor.http.*
import io.ktor.server.application.*
import io.ktor.server.auth.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import io.ktor.server.testing.*
import io.ktor.test.dispatcher.*
import org.junit.AfterClass
import org.junit.BeforeClass
import org.junit.Test
import uk.gov.communities.delta.auth.config.Client
import uk.gov.communities.delta.auth.security.ClientHeaderAuthProvider
import uk.gov.communities.delta.auth.security.clientHeaderAuth
import kotlin.test.assertContains
import kotlin.test.assertEquals

class ClientHeaderAuthProviderTest {

    @Test
    fun testUnauthorisedWithNoHeader() = testSuspend {
        testApp.client.get("/authenticated").apply {
            assertEquals(HttpStatusCode.Unauthorized, status)
            assertContains(bodyAsText(), "header required")
        }
    }

    @Test
    fun testUnauthorisedWithIncorrectSecret() = testSuspend {
        testApp.client.get("/authenticated") {
            headers {
                append("Test-Client-Auth", "test-client:bad-secret")
            }
        }.apply {
            assertEquals(HttpStatusCode.Unauthorized, status)
            assertContains(bodyAsText(), "Invalid client id or secret")
        }
    }

    @Test
    fun testAuthenticates() = testSuspend {
        testApp.client.get("/authenticated") {
            headers {
                append("Test-Client-Auth", "test-client:test-secret")
            }
        }.apply {
            assertEquals(HttpStatusCode.OK, status)
            assertEquals(bodyAsText(), "test-client")
        }
    }

    companion object {
        private lateinit var testApp: TestApplication

        @BeforeClass
        @JvmStatic
        fun setup() {
            testApp = TestApplication {
                application {
                    authentication {
                        clientHeaderAuth("test-client-auth-provider") {
                            headerName = "Test-Client-Auth"
                            clients = listOf(Client("test-client", "test-secret"))
                        }
                    }
                    routing {
                        authenticate("test-client-auth-provider", strategy = AuthenticationStrategy.Required) {
                            get("/authenticated") {
                                call.respondText(
                                    call.principal<ClientHeaderAuthProvider.ClientPrincipal>(
                                        "test-client-auth-provider"
                                    )!!.clientId
                                )
                            }
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
