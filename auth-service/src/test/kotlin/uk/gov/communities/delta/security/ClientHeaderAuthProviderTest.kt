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
import uk.gov.communities.delta.auth.security.ClientPrincipal
import uk.gov.communities.delta.auth.security.clientHeaderAuth
import uk.gov.communities.delta.helper.testServiceClient
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
                append("Test-Client-Auth", "${serviceClient.clientId}:bad-secret")
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
                append("Test-Client-Auth", "${serviceClient.clientId}:${serviceClient.clientSecret}")
            }
        }.apply {
            assertEquals(HttpStatusCode.OK, status)
            assertEquals(bodyAsText(), serviceClient.clientId)
        }
    }

    companion object {
        private lateinit var testApp: TestApplication
        private val serviceClient = testServiceClient()

        @BeforeClass
        @JvmStatic
        fun setup() {
            testApp = TestApplication {
                application {
                    authentication {
                        clientHeaderAuth("test-client-auth-provider") {
                            headerName = "Test-Client-Auth"
                            clients = listOf(serviceClient)
                        }
                    }
                    routing {
                        authenticate("test-client-auth-provider", strategy = AuthenticationStrategy.Required) {
                            get("/authenticated") {
                                call.respondText(
                                    call.principal<ClientPrincipal>(
                                        "test-client-auth-provider"
                                    )!!.client.clientId
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
