package uk.gov.communities.delta.controllers

import io.ktor.client.*
import io.ktor.client.request.*
import io.ktor.client.statement.*
import io.ktor.http.*
import io.ktor.server.auth.*
import io.ktor.server.routing.*
import io.ktor.server.testing.*
import io.ktor.test.dispatcher.*
import io.mockk.coEvery
import io.mockk.mockk
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.*
import org.junit.AfterClass
import org.junit.Assert
import org.junit.BeforeClass
import org.junit.Test
import uk.gov.communities.delta.auth.bearerTokenRoutes
import uk.gov.communities.delta.auth.config.DeltaConfig
import uk.gov.communities.delta.auth.controllers.internal.AdminEmailController
import uk.gov.communities.delta.auth.controllers.internal.AdminUserCreationController
import uk.gov.communities.delta.auth.controllers.internal.FetchUserAuditController
import uk.gov.communities.delta.auth.controllers.internal.RefreshUserInfoController
import uk.gov.communities.delta.auth.plugins.configureSerialization
import uk.gov.communities.delta.auth.repositories.UserAuditTrailRepo
import uk.gov.communities.delta.auth.security.CLIENT_HEADER_AUTH_NAME
import uk.gov.communities.delta.auth.security.OAUTH_ACCESS_BEARER_TOKEN_AUTH_NAME
import uk.gov.communities.delta.auth.security.clientHeaderAuth
import uk.gov.communities.delta.auth.services.OAuthSession
import uk.gov.communities.delta.auth.services.OAuthSessionService
import uk.gov.communities.delta.auth.services.UserAuditService
import uk.gov.communities.delta.auth.services.UserLookupService
import uk.gov.communities.delta.helper.testLdapUser
import uk.gov.communities.delta.helper.testServiceClient
import java.sql.Timestamp
import java.time.Instant
import kotlin.test.assertEquals


class FetchUserAuditControllerTest {

    @Test
    fun testAuditEndpoint() = testSuspend {
        testClient.get("/bearer/user-audit?cn=user") {
            headers {
                append("Authorization", "Bearer ${adminSession.authToken}")
                append("Delta-Client", "${client.clientId}:${client.clientSecret}")
            }
        }.apply {
            assertEquals(HttpStatusCode.OK, status)
            val response = Json.parseToJsonElement(bodyAsText()).jsonObject["userAudit"]!!.jsonArray
            assertEquals(1, response.size)
            assertEquals(
                UserAuditTrailRepo.AuditAction.SET_PASSWORD_EMAIL.action,
                response[0].jsonObject["action"]!!.jsonPrimitive.content
            )
        }
    }

    @Test
    fun testUserCanReadOwnAudit() = testSuspend {
        testClient.get("/bearer/user-audit?cn=user") {
            headers {
                append("Authorization", "Bearer ${userSession.authToken}")
                append("Delta-Client", "${client.clientId}:${client.clientSecret}")
            }
        }.apply {
            assertEquals(HttpStatusCode.OK, status)
        }
    }

    @Test
    fun testUserCannotReadAdminAudit() {
        Assert.assertThrows(FetchUserAuditController.AccessDeniedError::class.java) {
            runBlocking {
                testClient.get("/bearer/user-audit?cn=admin") {
                    headers {
                        append("Authorization", "Bearer ${userSession.authToken}")
                        append("Delta-Client", "${client.clientId}:${client.clientSecret}")
                    }
                }
            }
        }
    }

    @Test
    fun testActionDataSerialisedCorrectly() = testSuspend {
        testClient.get("/bearer/user-audit?cn=admin") {
            headers {
                append("Authorization", "Bearer ${adminSession.authToken}")
                append("Delta-Client", "${client.clientId}:${client.clientSecret}")
            }
        }.apply {
            assertEquals(HttpStatusCode.OK, status)
            assertEquals(
                "{\"userAudit\":[{\"action\":\"sso_login\",\"timestamp\":\"1970-01-01T00:00:01Z\",\"userCN\":\"admin\"," +
                        "\"editingUserCN\":null,\"requestId\":\"adminRequestId\"," +
                        "\"actionData\":{\"azureObjectId\":\"oid\"}}]}",
                bodyAsText()
            )
        }
    }

    @Test
    fun testCSVDownload() = testSuspend {
        testClient.get("/bearer/user-audit/csv?cn=admin") {
            headers {
                append("Authorization", "Bearer ${adminSession.authToken}")
                append("Delta-Client", "${client.clientId}:${client.clientSecret}")
                set("Accept", "application/csv")
            }
        }.apply {
            assertEquals(HttpStatusCode.OK, status)
            assertEquals(
                """
                    action,timestamp,userCN,editingUserCN,requestId,azureObjectId
                    sso_login,1970-01-01T00:00:01Z,admin,,adminRequestId,oid
                    
                """.trimIndent(),
                bodyAsText()
            )
        }
    }

    companion object {
        private lateinit var testApp: TestApplication
        private lateinit var testClient: HttpClient
        private lateinit var controller: FetchUserAuditController

        private val client = testServiceClient()
        private val adminUser = testLdapUser(cn = "admin", memberOfCNs = listOf(DeltaConfig.DATAMART_DELTA_ADMIN))
        private val regularUser = testLdapUser(cn = "user", memberOfCNs = emptyList())
        private val adminSession = OAuthSession(1, adminUser.cn, client, "adminAccessToken", Instant.now(), "trace", false)
        private val userSession = OAuthSession(1, regularUser.cn, client, "userAccessToken", Instant.now(), "trace", false)

        @BeforeClass
        @JvmStatic
        fun setup() {
            val userLookupService = mockk<UserLookupService>()
            val oauthSessionService = mockk<OAuthSessionService>()
            val userAuditService = mockk<UserAuditService>()

            // Auth mocks
            coEvery { userLookupService.lookupUserByCn(adminUser.cn) } answers { adminUser }
            coEvery { userLookupService.lookupUserByCn(regularUser.cn) } answers { regularUser }
            coEvery { oauthSessionService.retrieveFomAuthToken(any(), client) } answers { null }
            coEvery {
                oauthSessionService.retrieveFomAuthToken(
                    adminSession.authToken,
                    client
                )
            } answers { adminSession }
            coEvery { oauthSessionService.retrieveFomAuthToken(userSession.authToken, client) } answers { userSession }

            // Audit info mocks
            coEvery { userAuditService.getAuditForUser(regularUser.cn) } returns listOf(
                UserAuditTrailRepo.UserAuditRow(
                    UserAuditTrailRepo.AuditAction.SET_PASSWORD_EMAIL,
                    Timestamp(0),
                    regularUser.cn,
                    adminUser.cn,
                    "userRequestId",
                    JsonObject(emptyMap())
                )
            )
            coEvery { userAuditService.getAuditForUser(adminUser.cn) } returns listOf(
                UserAuditTrailRepo.UserAuditRow(
                    UserAuditTrailRepo.AuditAction.SSO_LOGIN,
                    Timestamp(1000),
                    adminUser.cn,
                    null,
                    "adminRequestId",
                    JsonObject(mapOf("azureObjectId" to JsonPrimitive("oid")))
                )
            )

            controller = FetchUserAuditController(
                userLookupService,
                userAuditService,
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
                            mockk<RefreshUserInfoController>(relaxed = true),
                            mockk<AdminEmailController>(relaxed = true),
                            controller,
                            mockk<AdminUserCreationController>(relaxed = true),
                            mockk(relaxed = true),
                            mockk(relaxed = true),
                            mockk(relaxed = true),
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
