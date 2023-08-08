package uk.gov.communities.delta.controllers

import io.ktor.client.*
import io.ktor.client.request.forms.*
import io.ktor.client.statement.*
import io.ktor.http.*
import io.ktor.server.routing.*
import io.ktor.server.testing.*
import io.ktor.test.dispatcher.*
import io.mockk.every
import io.mockk.mockk
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import org.junit.AfterClass
import org.junit.BeforeClass
import org.junit.Test
import uk.gov.communities.delta.auth.controllers.internal.OAuthTokenController
import uk.gov.communities.delta.auth.plugins.configureSerialization
import uk.gov.communities.delta.auth.saml.SAMLTokenService
import uk.gov.communities.delta.auth.services.*
import uk.gov.communities.delta.helper.testServiceClient
import java.time.Instant
import kotlin.test.assertContains
import kotlin.test.assertEquals


class OAuthTokenControllerTest {

    @Test
    fun testTokenEndpoint() = testSuspend {
        testClient.submitForm(
            url = "/token",
            formParameters = parameters {
                append("code", "code")
                append("client_id", client.clientId)
                append("client_secret", client.clientSecret)
            }
        ).apply {
            assertEquals(HttpStatusCode.OK, status)
            val response = Json.parseToJsonElement(bodyAsText()).jsonObject
            assertEquals(session.authToken, response["access_token"].toString().trim('"'))
            assertEquals("SAML Token", response["saml_token"].toString().trim('"'))
            assertEquals("user", response["delta_ldap_user"]!!.jsonObject["cn"].toString().trim('"'))
        }
    }

    @Test
    fun testInvalidClientSecret() = testSuspend {
        testClient.submitForm(
            url = "/token",
            formParameters = parameters {
                append("code", "code")
                append("client_id", client.clientId)
                append("client_secret", "invalid")
            }
        ).apply {
            assertEquals(HttpStatusCode.BadRequest, status)
            assertContains(bodyAsText(), "invalid_client")
        }
    }

    @Test
    fun testInvalidCode() = testSuspend {
        testClient.submitForm(
            url = "/token",
            formParameters = parameters {
                append("code", "invalid")
                append("client_id", client.clientId)
                append("client_secret", client.clientSecret)
            }
        ).apply {
            assertEquals(HttpStatusCode.BadRequest, status)
            assertContains(bodyAsText(), "invalid_grant")
        }
    }

    companion object {
        private lateinit var testApp: TestApplication
        private lateinit var testClient: HttpClient
        private lateinit var controller: OAuthTokenController
        private val client = testServiceClient()

        private val authCode = AuthCode("code", "user", client, Instant.now(), "trace")
        private val session = OAuthSession(1, "user", client, "accessToken", Instant.now(), "trace")
        private val user = LdapUser("dn", "user", listOf("example-role"), "", "", "")

        private val authorizationCodeService = mockk<AuthorizationCodeService>()
        private val userLookupService = mockk<UserLookupService>()
        private val samlTokenService = mockk<SAMLTokenService>()
        private val oAuthSessionService = mockk<OAuthSessionService>()

        @BeforeClass
        @JvmStatic
        fun setup() {
            every { authorizationCodeService.lookupAndInvalidate(any(), client) } answers { null }
            every { authorizationCodeService.lookupAndInvalidate(authCode.code, client) } answers { authCode }
            every { oAuthSessionService.create(authCode, client) } answers { session }
            every { userLookupService.lookupUserByCn(authCode.userCn) } answers { user }
            every {
                samlTokenService.generate(
                    client.samlCredential,
                    user,
                    session.createdAt,
                    any()
                )
            } answers { "SAML Token" }
            controller = OAuthTokenController(
                listOf(client), authorizationCodeService, userLookupService, samlTokenService, oAuthSessionService
            )

            testApp = TestApplication {
                application {
                    configureSerialization()
                    routing {
                        route("/token") {
                            controller.route(this)
                        }
                    }
                }
            }
            testClient = testApp.createClient {
                followRedirects = false
            }
        }

        @AfterClass
        @JvmStatic
        fun tearDown() {
            testApp.stop()
        }
    }
}
