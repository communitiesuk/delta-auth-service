package uk.gov.communities.delta.controllers

import io.ktor.client.*
import io.ktor.client.request.*
import io.ktor.client.statement.*
import io.ktor.http.*
import io.ktor.server.auth.*
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
import uk.gov.communities.delta.auth.bearerTokenRoutes
import uk.gov.communities.delta.auth.config.Client
import uk.gov.communities.delta.auth.controllers.internal.RefreshUserInfoController
import uk.gov.communities.delta.auth.plugins.configureSerialization
import uk.gov.communities.delta.auth.saml.SAMLTokenService
import uk.gov.communities.delta.auth.security.CLIENT_HEADER_AUTH_NAME
import uk.gov.communities.delta.auth.security.OAUTH_ACCESS_BEARER_TOKEN_AUTH_NAME
import uk.gov.communities.delta.auth.security.clientHeaderAuth
import uk.gov.communities.delta.auth.services.LdapUser
import uk.gov.communities.delta.auth.services.OAuthSession
import uk.gov.communities.delta.auth.services.OAuthSessionService
import uk.gov.communities.delta.auth.services.UserLookupService
import java.time.Instant
import kotlin.test.assertEquals


class RefreshUserInfoControllerTest {

    @Test
    fun testUserInfoEndpoint() = testSuspend {
        testClient.get("/bearer/user-info") {
            headers {
                append("Authorization", "Bearer ${session.authToken}")
                append("Delta-Client", "test-client:test-secret")
            }
        }.apply {
            assertEquals(HttpStatusCode.OK, status)
            val response = Json.parseToJsonElement(bodyAsText()).jsonObject
            assertEquals("SAML Token", response["saml_token"].toString().trim('"'))
            assertEquals("user", response["delta_ldap_user"]!!.jsonObject["cn"].toString().trim('"'))
        }
    }

    @Test
    fun testInvalidBearerToken() = testSuspend {
        testClient.get("/bearer/user-info") {
            headers {
                append("Authorization", "Bearer invalid_token")
                append("Delta-Client", "test-client:test-secret")
            }
        }.apply {
            assertEquals(HttpStatusCode.Unauthorized, status)
        }
    }

    companion object {
        private lateinit var testApp: TestApplication
        private lateinit var testClient: HttpClient
        private lateinit var controller: RefreshUserInfoController

        private val session = OAuthSession(1, "user", "accessToken", Instant.now(), "trace")
        private val user = LdapUser("dn", "user", listOf("example-role"), "", "", "")

        private val userLookupService = mock<UserLookupService>()
        private val samlTokenService = mock<SAMLTokenService>()
        private val oAuthSessionService = mock<OAuthSessionService>()

        @BeforeClass
        @JvmStatic
        fun setup() {
            whenever(userLookupService.lookupUserByCn(session.userCn)).thenReturn(user)
            whenever(samlTokenService.generate(eq(user), eq(session.createdAt), any())).thenReturn("SAML Token")
            whenever(oAuthSessionService.retrieveFomAuthToken(session.authToken)).thenReturn(session)
            controller = RefreshUserInfoController(userLookupService, samlTokenService)

            testApp = TestApplication {
                application {
                    configureSerialization()
                    authentication {
                        bearer(OAUTH_ACCESS_BEARER_TOKEN_AUTH_NAME) {
                            realm = "auth-service"
                            authenticate {
                                oAuthSessionService.retrieveFomAuthToken(it.token)
                            }
                        }
                        clientHeaderAuth(CLIENT_HEADER_AUTH_NAME) {
                            headerName = "Delta-Client"
                            clients = listOf(Client("test-client", "test-secret"))
                        }
                    }
                    routing {
                        bearerTokenRoutes(controller)
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
