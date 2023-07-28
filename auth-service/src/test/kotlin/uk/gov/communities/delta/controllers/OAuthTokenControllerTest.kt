package uk.gov.communities.delta.controllers

import io.ktor.client.*
import io.ktor.client.request.forms.*
import io.ktor.client.statement.*
import io.ktor.http.*
import io.ktor.server.routing.*
import io.ktor.server.testing.*
import io.ktor.test.dispatcher.*
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import org.junit.AfterClass
import org.junit.BeforeClass
import org.junit.Test
import org.mockito.Mockito.mock
import org.mockito.kotlin.any
import org.mockito.kotlin.eq
import org.mockito.kotlin.whenever
import uk.gov.communities.delta.auth.config.OAuthClient
import uk.gov.communities.delta.auth.controllers.internal.OAuthTokenController
import uk.gov.communities.delta.auth.plugins.configureSerialization
import uk.gov.communities.delta.auth.saml.SAMLTokenService
import uk.gov.communities.delta.auth.services.*
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
        private val client= OAuthClient("delta-website", "secret", "https://delta/redirect")

        private val authCode = AuthCode("code", "user", client, Instant.now(), "trace")
        private val session = OAuthSession(1, "user", client, "accessToken", Instant.now(), "trace")
        private val user = LdapUser("dn", "user", listOf("example-role"), "", "", "")

        private val authorizationCodeService = mock<AuthorizationCodeService>()
        private val userLookupService = mock<UserLookupService>()
        private val samlTokenService = mock<SAMLTokenService>()
        private val oAuthSessionService = mock<OAuthSessionService>()

        @BeforeClass
        @JvmStatic
        fun setup() {
            whenever(authorizationCodeService.lookupAndInvalidate(authCode.code, client)).thenReturn(authCode)
            whenever(oAuthSessionService.create(authCode, client)).thenReturn(session)
            whenever(userLookupService.lookupUserByCn(authCode.userCn)).thenReturn(user)
            whenever(samlTokenService.generate(eq(user), eq(session.createdAt), any())).thenReturn("SAML Token")
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
