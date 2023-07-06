package uk.gov.communities.delta

import io.ktor.client.request.*
import io.ktor.client.statement.*
import io.ktor.http.*
import io.ktor.server.application.*
import io.ktor.server.auth.*
import io.ktor.server.routing.*
import io.ktor.server.testing.*
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import uk.gov.communities.delta.auth.config.ClientConfig
import uk.gov.communities.delta.auth.healthcheckRoute
import uk.gov.communities.delta.auth.internalRoutes
import uk.gov.communities.delta.auth.module
import uk.gov.communities.delta.auth.plugins.configureSerialization
import uk.gov.communities.delta.auth.security.*
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull

class ApplicationTest {
    @Test
    fun testRoot() = testApplication {
        application {
            module()
        }
        client.get("/").apply {
            assertEquals(HttpStatusCode.OK, status)
            assertEquals("Hello World!", bodyAsText())
        }
    }

    @Test
    fun testHealthcheck() = testApplication {
        application {
            routing {
                healthcheckRoute()
            }
        }
        client.get("/health").apply {
            assertEquals(HttpStatusCode.OK, status)
            assertEquals("OK", bodyAsText())
        }
    }

    @Test
    fun testGenerateSamlToken() = testApplication {
        application {
            configureSerialization()
            fakeSecurityConfig()
            routing {
                internalRoutes()
            }
        }
        client.post("/auth-internal/service-user/generate-saml-token") {
            headers {
                append(HttpHeaders.Accept, "application/json")
                append("Delta-Client", "test-client:test-secret")
                basicAuth("test-user", "pass")
            }
        }.apply {
            assertEquals(HttpStatusCode.OK, status)
            val json = Json.parseToJsonElement(bodyAsText())
            assertNotNull(json.jsonObject["token"])
        }
    }

    private fun Application.fakeSecurityConfig() {
        authentication {
            basic(DELTA_AD_LDAP_SERVICE_USERS_AUTH_NAME) {
                realm = "Delta"
                validate { credential ->
                    if (credential.password == "pass") {
                        DeltaLdapPrincipal(credential.name, listOf("test-role"))
                    } else {
                        null
                    }
                }
            }
            clientHeaderAuth(CLIENT_AUTH_NAME) {
                headerName = "Delta-Client"
                clients = listOf(ClientHeaderAuthProvider.Client("test-client", "test-secret"))
            }
        }
    }
}
