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
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.*
import org.junit.AfterClass
import org.junit.Assert
import org.junit.BeforeClass
import org.junit.Test
import uk.gov.communities.delta.auth.config.DeltaConfig
import uk.gov.communities.delta.auth.controllers.internal.FetchUserAuditController
import uk.gov.communities.delta.auth.plugins.ApiError
import uk.gov.communities.delta.auth.plugins.configureSerialization
import uk.gov.communities.delta.auth.repositories.UserAuditTrailRepo
import uk.gov.communities.delta.auth.security.CLIENT_HEADER_AUTH_NAME
import uk.gov.communities.delta.auth.security.OAUTH_ACCESS_BEARER_TOKEN_AUTH_NAME
import uk.gov.communities.delta.auth.security.clientHeaderAuth
import uk.gov.communities.delta.auth.services.OAuthSession
import uk.gov.communities.delta.auth.services.OAuthSessionService
import uk.gov.communities.delta.auth.services.UserAuditService
import uk.gov.communities.delta.auth.services.UserLookupService
import uk.gov.communities.delta.auth.withBearerTokenAuth
import uk.gov.communities.delta.helper.testLdapUser
import uk.gov.communities.delta.helper.testServiceClient
import java.sql.Timestamp
import java.time.Instant
import kotlin.test.assertContains
import kotlin.test.assertEquals


class FetchUserAuditControllerTest {

    @Test
    fun testAuditEndpoint() = testSuspend {
        testClient.get("/user-audit?cn=user") {
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
        testClient.get("/user-audit?cn=user") {
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
                testClient.get("/user-audit?cn=admin") {
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
        testClient.get("/user-audit?cn=admin") {
            headers {
                append("Authorization", "Bearer ${adminSession.authToken}")
                append("Delta-Client", "${client.clientId}:${client.clientSecret}")
            }
        }.apply {
            assertEquals(HttpStatusCode.OK, status)
            assertEquals(
                "{\"userAudit\":[{\"action\":\"sso_login\",\"timestamp\":\"1970-01-01T00:00:01Z\",\"userCN\":\"admin\"," +
                    "\"userGUID\":\"00112233-4455-6677-8899-aabbccddeeff\",\"editingUserCN\":null," +
                    "\"editingUserGUID\":\"\",\"requestId\":\"adminRequestId\"," +
                    "\"actionData\":{\"azureObjectId\":\"oid\"}}],\"totalRecords\":50}",
                bodyAsText()
            )
        }
    }

    @Test
    fun testCSVDownload() = testSuspend {
        testClient.get("/user-audit/csv?cn=admin") {
            headers {
                append("Authorization", "Bearer ${adminSession.authToken}")
                append("Delta-Client", "${client.clientId}:${client.clientSecret}")
                set("Accept", "application/csv")
            }
        }.apply {
            assertEquals(HttpStatusCode.OK, status)
            assertEquals(
                """
                    action,timestamp,userCN,userGUID,editingUserCN,editingUserGUID,requestId,azureObjectId
                    sso_login,1970-01-01T00:00:01Z,admin,00112233-4455-6677-8899-aabbccddeeff,,,adminRequestId,oid
                    
                """.trimIndent(),
                bodyAsText()
            )
        }
    }

    @Test
    fun testAllUserCSVDownload() = testSuspend {
        clearMocks(userAuditService, answers = false, recordedCalls = true, verificationMarks = true)
        testClient.get("/user-audit/all-csv?fromDate=2024-01-01&toDate=2024-08-01") {
            headers {
                append("Authorization", "Bearer ${adminSession.authToken}")
                append("Delta-Client", "${client.clientId}:${client.clientSecret}")
                set("Accept", "application/csv")
            }
        }.apply {
            assertEquals(HttpStatusCode.OK, status)
            coVerify {
                userAuditService.getAuditForAllUsers(
                    Instant.parse("2024-01-01T00:00:00Z"),
                    Instant.parse("2024-08-02T00:00:00+01:00")
                )
            }
            confirmVerified(userAuditService)
            assertEquals(
                """
                    action,timestamp,userCN,userGUID,editingUserCN,editingUserGUID,requestId,azureObjectId
                    set_password_email,1970-01-01T00:00:00Z,user,00112233-4455-6677-8899-aabbccddeeff,admin,00112233-4455-6677-8899-aabbccddeeff,userRequestId,
                    sso_login,1970-01-01T00:00:01Z,admin,00112233-4455-6677-8899-aabbccddeeff,,,adminRequestId,oid

                """.trimIndent(),
                bodyAsText()
            )
        }
    }

    @Test
    fun testRegularUserCannotReadAllUserAudit() {
        Assert.assertThrows(FetchUserAuditController.AccessDeniedError::class.java) {
            runBlocking {
                testClient.get("/user-audit/all-csv?fromDate=2024-01-01&toDate=2024-08-01") {
                    headers {
                        append("Authorization", "Bearer ${userSession.authToken}")
                        append("Delta-Client", "${client.clientId}:${client.clientSecret}")
                        set("Accept", "application/csv")
                    }
                }
            }
        }
    }

    @Test
    fun testReturnsBadRequestOnInvalidDate() {
        Assert.assertThrows(ApiError::class.java) {
            runBlocking {
                testClient.get("/user-audit/all-csv?fromDate=2024-01-40&toDate=2024-08-01") {
                    headers {
                        append("Authorization", "Bearer ${adminSession.authToken}")
                        append("Delta-Client", "${client.clientId}:${client.clientSecret}")
                        set("Accept", "application/csv")
                    }
                }
            }
        }.apply {
            assertEquals("bad_request", errorCode)
            assertContains(message!!, "Invalid date parameter 'fromDate'")
        }
    }

    companion object {
        private lateinit var testApp: TestApplication
        private lateinit var testClient: HttpClient
        private lateinit var controller: FetchUserAuditController
        private lateinit var userAuditService: UserAuditService

        private val client = testServiceClient()
        private val adminUser = testLdapUser(cn = "admin", memberOfCNs = listOf(DeltaConfig.DATAMART_DELTA_ADMIN))
        private val regularUser = testLdapUser(cn = "user", memberOfCNs = emptyList())
        private val adminSession = OAuthSession(
            1, adminUser.cn, adminUser.getGUID(), client, "adminAccessToken", Instant.now(), "trace", false
        )
        private val userSession = OAuthSession(
            1, regularUser.cn, regularUser.getGUID(), client, "userAccessToken", Instant.now(), "trace", false
        )

        @BeforeClass
        @JvmStatic
        fun setup() {
            val userLookupService = mockk<UserLookupService>()
            val oauthSessionService = mockk<OAuthSessionService>()
            userAuditService = mockk<UserAuditService>()

            // Auth mocks
            coEvery { userLookupService.lookupCurrentUser(adminSession) } answers { adminUser }
            coEvery { userLookupService.lookupCurrentUser(userSession) } answers { regularUser }
            coEvery { userLookupService.lookupUserByCn(regularUser.cn) } answers { regularUser } // TODO DT-976-2 - get rid of these hopefully
            coEvery { userLookupService.lookupUserByCn(adminUser.cn) } answers { adminUser }
            coEvery { oauthSessionService.retrieveFomAuthToken(any(), client) } answers { null }
            coEvery {
                oauthSessionService.retrieveFomAuthToken(
                    adminSession.authToken,
                    client
                )
            } answers { adminSession }
            coEvery { oauthSessionService.retrieveFomAuthToken(userSession.authToken, client) } answers { userSession }

            // Audit info mocks
            val userAudit = UserAuditTrailRepo.UserAuditRow(
                UserAuditTrailRepo.AuditAction.SET_PASSWORD_EMAIL,
                Timestamp(0),
                regularUser.cn,
                regularUser.getGUID(),
                    adminUser.cn,
                    adminUser.getGUID(),
                "userRequestId",
                JsonObject(emptyMap())
            )
            coEvery { userAuditService.getAuditForUser(regularUser.cn) } returns listOf(userAudit)
            coEvery { userAuditService.getAuditForUserPaged(regularUser.cn, 1, 100) } returns Pair(
                listOf(userAudit),
                50
            )
            val adminAudit = UserAuditTrailRepo.UserAuditRow(
                UserAuditTrailRepo.AuditAction.SSO_LOGIN,
                Timestamp(1000),
                adminUser.cn,
                adminUser.getGUID(),
                    null,
                    null,
                    "adminRequestId",
                    JsonObject(mapOf("azureObjectId" to JsonPrimitive("oid")))
                )
            coEvery { userAuditService.getAuditForUser(adminUser.cn) } returns listOf(adminAudit)
            coEvery { userAuditService.getAuditForUserPaged(adminUser.cn, 1, 100) } returns Pair(
                listOf(adminAudit),
                50
            )
            coEvery { userAuditService.getAuditForAllUsers(any(), any()) } returns listOf(userAudit, adminAudit)

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
                        withBearerTokenAuth {
                            route("/user-audit") {
                                controller.route(this)
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
