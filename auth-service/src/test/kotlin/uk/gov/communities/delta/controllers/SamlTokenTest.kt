package uk.gov.communities.delta.controllers

import io.ktor.client.request.*
import io.ktor.client.statement.*
import io.ktor.http.*
import io.ktor.server.application.*
import io.ktor.server.auth.*
import io.ktor.server.routing.*
import io.ktor.server.testing.*
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import org.junit.Test
import uk.gov.communities.delta.auth.config.Client
import uk.gov.communities.delta.auth.config.SAMLConfig
import uk.gov.communities.delta.auth.controllers.internal.GenerateSAMLTokenController
import uk.gov.communities.delta.auth.plugins.configureSerialization
import uk.gov.communities.delta.auth.saml.SAMLTokenService
import uk.gov.communities.delta.auth.security.CLIENT_HEADER_AUTH_NAME
import uk.gov.communities.delta.auth.security.DELTA_AD_LDAP_SERVICE_USERS_AUTH_NAME
import uk.gov.communities.delta.auth.security.DeltaLdapPrincipal
import uk.gov.communities.delta.auth.security.clientHeaderAuth
import uk.gov.communities.delta.auth.serviceUserRoutes
import uk.gov.communities.delta.helper.testLdapUser
import kotlin.test.assertEquals
import kotlin.test.assertNotNull

class SamlTokenTest {
    @Test
    fun testGenerateSamlToken() = testApplication {
        application {
            configureSerialization()
            fakeSecurityConfig()
            val controller = GenerateSAMLTokenController(SAMLTokenService())
            routing {
                serviceUserRoutes(controller)
            }
        }
        client.post("/service-user/generate-saml-token") {
            headers {
                append(HttpHeaders.Accept, "application/json")
                append("Delta-Client", "${serviceClient.clientId}:${serviceClient.clientSecret}")
                basicAuth("test-user", "pass")
            }
        }.apply {
            assertEquals(HttpStatusCode.OK, status)
            val json = Json.parseToJsonElement(bodyAsText())
            assertNotNull(json.jsonObject["token"])
        }
    }

    private val serviceClient = Client("test-client", "test-secret", SAMLConfig.insecureHardcodedCredentials())
    private fun Application.fakeSecurityConfig() {
        authentication {
            basic(DELTA_AD_LDAP_SERVICE_USERS_AUTH_NAME) {
                realm = "Delta"
                validate { credential ->
                    if (credential.password == "pass") {
                        DeltaLdapPrincipal(testLdapUser(cn = credential.name, memberOfCNs = listOf("test-role")))
                    } else {
                        null
                    }
                }
            }
            clientHeaderAuth(CLIENT_HEADER_AUTH_NAME) {
                headerName = "Delta-Client"
                clients = listOf(serviceClient)
            }
        }
    }
}
