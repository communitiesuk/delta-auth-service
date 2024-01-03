package uk.gov.communities.delta.controllers

import io.ktor.client.*
import io.ktor.client.request.*
import io.ktor.client.statement.*
import io.ktor.http.*
import io.ktor.server.auth.*
import io.ktor.server.routing.*
import io.ktor.server.testing.*
import io.ktor.test.dispatcher.*
import io.mockk.*
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.AfterClass
import org.junit.BeforeClass
import org.junit.Test
import uk.gov.communities.delta.auth.bearerTokenRoutes
import uk.gov.communities.delta.auth.controllers.internal.AdminEmailController
import uk.gov.communities.delta.auth.controllers.internal.AdminUserCreationController
import uk.gov.communities.delta.auth.controllers.internal.FetchUserAuditController
import uk.gov.communities.delta.auth.controllers.internal.RefreshUserInfoController
import uk.gov.communities.delta.auth.plugins.configureSerialization
import uk.gov.communities.delta.auth.saml.SAMLTokenService
import uk.gov.communities.delta.auth.security.CLIENT_HEADER_AUTH_NAME
import uk.gov.communities.delta.auth.security.OAUTH_ACCESS_BEARER_TOKEN_AUTH_NAME
import uk.gov.communities.delta.auth.security.clientHeaderAuth
import uk.gov.communities.delta.auth.services.*
import uk.gov.communities.delta.helper.testLdapUser
import uk.gov.communities.delta.helper.testServiceClient
import java.time.Instant
import kotlin.test.assertEquals


class RefreshUserInfoControllerTest {

    @Test
    fun testUserInfoEndpoint() = testSuspend {
        testClient.get("/bearer/user-info") {
            headers {
                append("Authorization", "Bearer ${session.authToken}")
                append("Delta-Client", "${client.clientId}:${client.clientSecret}")
            }
        }.apply {
            assertEquals(HttpStatusCode.OK, status)
            val response = Json.parseToJsonElement(bodyAsText()).jsonObject
            assertEquals("SAML Token", response["saml_token"].toString().trim('"'))
            assertEquals("user", response["delta_ldap_user"]!!.jsonObject["cn"].toString().trim('"'))
            assertEquals(
                "dclg",
                response["delta_user_roles"]!!.jsonObject["organisations"]!!.jsonArray.single().jsonObject["code"]!!.jsonPrimitive.content
            )
        }
    }

    @Test
    fun testInvalidBearerToken() = testSuspend {
        testClient.get("/bearer/user-info") {
            headers {
                append("Authorization", "Bearer invalid_token")
                append("Delta-Client", "${client.clientId}:${client.clientSecret}")
            }
        }.apply {
            assertEquals(HttpStatusCode.Unauthorized, status)
        }
    }

    companion object {
        private lateinit var testApp: TestApplication
        private lateinit var testClient: HttpClient
        private lateinit var controller: RefreshUserInfoController

        private val client = testServiceClient()
        private val session = OAuthSession(1, "user", client, "accessToken", Instant.now(), "trace")
        private val user = testLdapUser(cn = "user", memberOfCNs = listOf("datamart-delta-user-dclg"))

        @BeforeClass
        @JvmStatic
        fun setup() {
            val userLookupService = mockk<UserLookupService>()
            val samlTokenService = mockk<SAMLTokenService>()
            val oauthSessionService = mockk<OAuthSessionService>()
            val accessGroupsService = mockk<AccessGroupsService>()
            val organisationService = mockk<OrganisationService>()
            val adminEmailController = mockk<AdminEmailController>()

            coEvery { userLookupService.lookupUserByCn(session.userCn) } answers { user }
            every {
                samlTokenService.generate(
                    client.samlCredential,
                    user,
                    session.createdAt,
                    any()
                )
            } answers { "SAML Token" }
            coEvery { accessGroupsService.getAllAccessGroups() }.returns(listOf())
            coEvery { organisationService.findAllNamesAndCodes() }.returns(
                listOf(OrganisationNameAndCode("dclg", "The Department"))
            )
            coEvery { oauthSessionService.retrieveFomAuthToken(any(), client) } answers { null }
            coEvery { oauthSessionService.retrieveFomAuthToken(session.authToken, client) } answers { session }
            coEvery { adminEmailController.route(any()) } just runs

            controller = RefreshUserInfoController(
                userLookupService,
                samlTokenService,
                accessGroupsService,
                organisationService,
                ::MemberOfToDeltaRolesMapper
            )
            testApp = TestApplication {
                application {
                    configureSerialization()
                    authentication {
                        bearer(OAUTH_ACCESS_BEARER_TOKEN_AUTH_NAME) {
                            realm = "auth-service"
                            authenticate {
                                oauthSessionService.retrieveFomAuthToken(it.token, client)
                            }
                        }
                        clientHeaderAuth(CLIENT_HEADER_AUTH_NAME) {
                            headerName = "Delta-Client"
                            clients = listOf(testServiceClient())
                        }
                    }
                    routing {
                        bearerTokenRoutes(
                            controller,
                            adminEmailController,
                            mockk<FetchUserAuditController>(relaxed = true),
                            mockk<AdminUserCreationController>(relaxed = true),
                        )
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
