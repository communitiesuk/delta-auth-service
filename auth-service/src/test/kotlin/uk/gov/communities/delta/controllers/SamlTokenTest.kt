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
import kotlinx.serialization.json.jsonPrimitive
import net.shibboleth.shared.xml.impl.BasicParserPool
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport
import org.opensaml.core.xml.schema.XSString
import org.opensaml.saml.common.SAMLVersion
import org.opensaml.saml.saml2.core.Response
import org.opensaml.saml.saml2.core.StatusCode
import org.opensaml.xmlsec.signature.support.SignatureConstants
import org.opensaml.xmlsec.signature.support.SignatureValidator
import org.junit.Test
import uk.gov.communities.delta.auth.config.Client
import uk.gov.communities.delta.auth.config.LDAPConfig
import uk.gov.communities.delta.auth.config.SAMLConfig
import uk.gov.communities.delta.auth.controllers.internal.GenerateSAMLTokenController
import uk.gov.communities.delta.auth.plugins.configureSerialization
import uk.gov.communities.delta.auth.saml.SAMLTokenService
import uk.gov.communities.delta.auth.samlTokenRoutes
import uk.gov.communities.delta.auth.security.CLIENT_HEADER_AUTH_NAME
import uk.gov.communities.delta.auth.security.DELTA_AD_LDAP_SERVICE_USERS_AUTH_NAME
import uk.gov.communities.delta.auth.security.DeltaLdapPrincipal
import uk.gov.communities.delta.auth.security.clientHeaderAuth
import uk.gov.communities.delta.helper.testLdapUser
import uk.gov.communities.delta.helper.testOpenTelemetry
import java.io.ByteArrayInputStream
import java.time.Instant
import java.util.Base64
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class SamlTokenTest {
    @Test
    fun testGenerateSamlToken() = testApplication {
        application {
            configureSerialization()
            fakeSecurityConfig()
            val controller =
                GenerateSAMLTokenController(SAMLTokenService(testOpenTelemetry.getTracer("test-generate-saml")))
            routing {
                route("/service-user") {
                    authenticate(DELTA_AD_LDAP_SERVICE_USERS_AUTH_NAME, strategy = AuthenticationStrategy.Required) {
                        samlTokenRoutes(controller)
                    }
                }
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
            val json = Json.parseToJsonElement(bodyAsText()).jsonObject
            val token = assertNotNull(json["token"]).jsonPrimitive.content
            val expiry = Instant.parse(assertNotNull(json["expiry"]).jsonPrimitive.content)
            val response = parseSamlResponse(token)
            val assertion = response.assertions.single()
            val status = assertNotNull(response.status)
            val statusCode = assertNotNull(status.statusCode)
            val issuer = assertNotNull(assertion.issuer)
            val subject = assertNotNull(assertion.subject)
            val nameId = assertNotNull(subject.nameID)
            val conditions = assertNotNull(assertion.conditions)
            val notBefore = assertNotNull(conditions.notBefore)
            val notOnOrAfter = assertNotNull(conditions.notOnOrAfter)

            assertEquals(SAMLVersion.VERSION_20, response.version)
            assertEquals(StatusCode.SUCCESS, statusCode.value)
            assertEquals(assertion.issueInstant, response.issueInstant)
            assertEquals(assertion.id + "-1", response.id)
            assertEquals("marklogicsp", issuer.value)
            assertEquals("test-user", nameId.value)
            assertEquals("api-ml-saml", conditions.audienceRestrictions.single().audiences.single().uri)
            assertEquals(expiry, notOnOrAfter)
            assertTrue(notBefore.isBefore(notOnOrAfter))

            val roleAttribute = assertion.attributeStatements.single().attributes.single()
            assertEquals("Role", roleAttribute.name)
            assertEquals(expectedRole, (roleAttribute.attributeValues.single() as XSString).value)

            val signature = assertNotNull(assertion.signature)
            assertEquals(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA256, signature.signatureAlgorithm)
            assertEquals(SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS, signature.canonicalizationAlgorithm)
            SignatureValidator.validate(signature, serviceClient.samlCredential)
        }
    }

    private val serviceClient = Client("test-client", "test-secret", SAMLConfig.insecureHardcodedCredentials())
    private val expectedRole = LDAPConfig.DATAMART_DELTA_PREFIX + "test-role"

    private fun parseSamlResponse(encodedToken: String): Response {
        val parserPool = BasicParserPool().apply { initialize() }
        val document = parserPool.parse(ByteArrayInputStream(Base64.getDecoder().decode(encodedToken)))
        val unmarshaller = assertNotNull(
            XMLObjectProviderRegistrySupport.getUnmarshallerFactory().getUnmarshaller(document.documentElement)
        )
        return unmarshaller.unmarshall(document.documentElement) as Response
    }

    private fun Application.fakeSecurityConfig() {
        authentication {
            basic(DELTA_AD_LDAP_SERVICE_USERS_AUTH_NAME) {
                realm = "Delta"
                validate { credential ->
                    if (credential.password == "pass") {
                        DeltaLdapPrincipal(
                            testLdapUser(
                                cn = credential.name,
                                memberOfCNs = listOf(expectedRole),
                                email = null
                            )
                        )
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
