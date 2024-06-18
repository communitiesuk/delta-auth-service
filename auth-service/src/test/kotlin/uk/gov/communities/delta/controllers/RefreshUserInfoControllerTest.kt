package uk.gov.communities.delta.controllers

import io.ktor.client.*
import io.ktor.client.request.*
import io.ktor.client.statement.*
import io.ktor.http.*
import io.ktor.server.application.*
import io.ktor.server.auth.*
import io.ktor.server.plugins.callid.*
import io.ktor.server.routing.*
import io.ktor.server.testing.*
import io.ktor.test.dispatcher.*
import io.mockk.*
import kotlinx.serialization.json.*
import org.junit.AfterClass
import org.junit.BeforeClass
import org.junit.Test
import uk.gov.communities.delta.auth.config.DeltaConfig
import uk.gov.communities.delta.auth.controllers.internal.AdminEmailController
import uk.gov.communities.delta.auth.controllers.internal.RefreshUserInfoController
import uk.gov.communities.delta.auth.plugins.ApiError
import uk.gov.communities.delta.auth.plugins.configureSerialization
import uk.gov.communities.delta.auth.saml.SAMLTokenService
import uk.gov.communities.delta.auth.security.CLIENT_HEADER_AUTH_NAME
import uk.gov.communities.delta.auth.security.OAUTH_ACCESS_BEARER_TOKEN_AUTH_NAME
import uk.gov.communities.delta.auth.security.clientHeaderAuth
import uk.gov.communities.delta.auth.services.*
import uk.gov.communities.delta.auth.withBearerTokenAuth
import uk.gov.communities.delta.helper.testLdapUser
import uk.gov.communities.delta.helper.testServiceClient
import java.time.Instant
import kotlin.test.assertEquals


class RefreshUserInfoControllerTest {

    @Test
    fun testUserInfoEndpoint() = testSuspend {
        testClient.get("/user-info") {
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
        testClient.get("/user-info") {
            headers {
                append("Authorization", "Bearer invalid_token")
                append("Delta-Client", "${client.clientId}:${client.clientSecret}")
            }
        }.apply {
            assertEquals(HttpStatusCode.Unauthorized, status)
        }
    }

    @Test
    fun testImpersonateUserEndpoint() = testSuspend {
        testClient.post("/user-impersonate?userToImpersonate=${userToImpersonate.cn}") {
            headers {
                append("Authorization", "Bearer ${adminSession.authToken}")
                append("Delta-Client", "${client.clientId}:${client.clientSecret}")
            }
        }.apply {
            assertEquals(HttpStatusCode.OK, status)
            val response = Json.parseToJsonElement(bodyAsText()).jsonObject
            assertEquals("Admin With Impersonated Groups SAML Token", response["saml_token"].toString().trim('"'))
            assertEquals("adminUser", response["delta_ldap_user"]!!.jsonObject["cn"].toString().trim('"'))
            assert(
                response["delta_user_roles"]!!.jsonObject["systemRoles"]!!.jsonArray.any<JsonElement> {
                    it.jsonObject["name"]!!.jsonPrimitive.content == "read-only-admin"
                }
            )
        }
    }

    @Test(expected = ApiError::class)
    fun testImpersonateUserEndpointAsNonAdmin() = testSuspend {
        testClient.post("/user-impersonate?userToImpersonate=${userToImpersonate.cn}") {
            headers {
                append("Authorization", "Bearer ${session.authToken}")
                append("Delta-Client", "${client.clientId}:${client.clientSecret}")
            }
        }
    }

    companion object {
        private lateinit var testApp: TestApplication
        private lateinit var testClient: HttpClient
        private lateinit var controller: RefreshUserInfoController

        private val client = testServiceClient()
        private val user = testLdapUser(cn = "user", memberOfCNs = listOf("datamart-delta-user-dclg"))
        private val adminUser = testLdapUser(cn = "adminUser", memberOfCNs = listOf(DeltaConfig.DATAMART_DELTA_ADMIN))
        private val session =
            OAuthSession(1, user.cn, user.getGUID(), client, "accessToken", Instant.now(), "trace", false)
        private val adminSession = OAuthSession(
            2, adminUser.cn, adminUser.getGUID(), client, "adminAccessToken", Instant.now(), "trace", false
        )
        private val userToImpersonate =
            testLdapUser(
                cn = "userToImpersonate",
                memberOfCNs = listOf(DeltaConfig.DATAMART_DELTA_USER, DeltaConfig.DATAMART_DELTA_READ_ONLY_ADMIN)
            )
        private val adminImpersonatingUser =
            testLdapUser(
                cn = adminUser.cn,
                memberOfCNs = userToImpersonate.memberOfCNs,
                javaUUIDObjectGuid = adminUser.javaUUIDObjectGuid
            )

        @BeforeClass
        @JvmStatic
        fun setup() {
            val userLookupService = mockk<UserLookupService>()
            val userGUIDMapService = mockk<UserGUIDMapService>()
            val samlTokenService = mockk<SAMLTokenService>()
            val oauthSessionService = mockk<OAuthSessionService>()
            val accessGroupsService = mockk<AccessGroupsService>()
            val organisationService = mockk<OrganisationService>()
            val adminEmailController = mockk<AdminEmailController>()
            val userAuditService = mockk<UserAuditService>()



            coEvery { userLookupService.lookupCurrentUser(session) } answers { user }
            coEvery { userLookupService.lookupCurrentUser(adminSession) } answers { adminUser }
            coEvery { userGUIDMapService.getGUIDFromCN(userToImpersonate.cn) } returns userToImpersonate.getGUID()
            coEvery { userLookupService.lookupUserByGUID(userToImpersonate.getGUID()) } returns userToImpersonate
            every {
                samlTokenService.generate(
                    client.samlCredential,
                    user,
                    session.createdAt,
                    any()
                )
            } answers { "SAML Token" }
            every {
                samlTokenService.generate(
                    client.samlCredential,
                    adminImpersonatingUser,
                    adminSession.createdAt,
                    any()
                )
            } answers { "Admin With Impersonated Groups SAML Token" }
            coEvery { accessGroupsService.getAllAccessGroups() }.returns(listOf())
            coEvery { organisationService.findAllNamesAndCodes() }.returns(
                listOf(OrganisationNameAndCode("dclg", "The Department"))
            )
            coEvery { oauthSessionService.retrieveFromAuthToken(any(), client) } answers { null }
            coEvery { oauthSessionService.retrieveFromAuthToken(session.authToken, client) } answers { session }
            coEvery {
                oauthSessionService.retrieveFromAuthToken(adminSession.authToken, client)
            } answers { adminSession }
            coEvery {
                oauthSessionService.updateWithImpersonatedGUID(adminSession.id, userToImpersonate.getGUID())
            } just runs
            coEvery { adminEmailController.route(any()) } just runs
            coEvery {
                userAuditService.insertImpersonatingUserAuditRow(
                    adminSession,
                    userToImpersonate.getGUID(),
                    any()
                )
            } just runs

            controller = RefreshUserInfoController(
                userLookupService,
                userGUIDMapService,
                samlTokenService,
                accessGroupsService,
                organisationService,
                ::MemberOfToDeltaRolesMapper,
                oauthSessionService,
                userAuditService
            )
            testApp = TestApplication {
                install(CallId) { generate(4) }
                application {
                    configureSerialization()
                    authentication {
                        bearer(OAUTH_ACCESS_BEARER_TOKEN_AUTH_NAME) {
                            realm = "auth-service"
                            authenticate {
                                oauthSessionService.retrieveFromAuthToken(it.token, client)
                            }
                        }
                        clientHeaderAuth(CLIENT_HEADER_AUTH_NAME) {
                            headerName = "Delta-Client"
                            clients = listOf(testServiceClient())
                        }
                    }
                    routing {
                        withBearerTokenAuth {
                            get("/user-info") {
                                controller.refreshUserInfo(call)
                            }
                            post("/user-impersonate") {
                                controller.impersonateUser(call)
                            }
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
