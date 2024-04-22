package uk.gov.communities.delta.controllers

import io.ktor.client.*
import io.ktor.client.plugins.contentnegotiation.*
import io.ktor.client.request.*
import io.ktor.client.statement.*
import io.ktor.http.*
import io.ktor.serialization.kotlinx.json.*
import io.ktor.server.auth.*
import io.ktor.server.routing.*
import io.ktor.server.testing.*
import io.ktor.test.dispatcher.*
import io.mockk.clearAllMocks
import io.mockk.coEvery
import io.mockk.mockk
import kotlinx.coroutines.runBlocking
import org.junit.AfterClass
import org.junit.Assert
import org.junit.Before
import org.junit.BeforeClass
import uk.gov.communities.delta.auth.config.DeltaConfig
import uk.gov.communities.delta.auth.controllers.internal.AdminGetUserController
import uk.gov.communities.delta.auth.plugins.ApiError
import uk.gov.communities.delta.auth.plugins.configureSerialization
import uk.gov.communities.delta.auth.security.CLIENT_HEADER_AUTH_NAME
import uk.gov.communities.delta.auth.security.OAUTH_ACCESS_BEARER_TOKEN_AUTH_NAME
import uk.gov.communities.delta.auth.security.clientHeaderAuth
import uk.gov.communities.delta.auth.services.*
import uk.gov.communities.delta.auth.withBearerTokenAuth
import uk.gov.communities.delta.helper.mockUserLookupService
import uk.gov.communities.delta.helper.testLdapUser
import uk.gov.communities.delta.helper.testServiceClient
import java.time.Instant
import kotlin.test.Test
import kotlin.test.assertEquals

class AdminGetUserControllerTest {

    @Test
    fun testAdminGetUser() = testSuspend {
        testClient.get("/get-user?userCn=${user.cn}") {
            headers {
                append("Authorization", "Bearer ${adminSession.authToken}")
                append("Delta-Client", "${client.clientId}:${client.clientSecret}")
            }
        }.apply {
            assertEquals(HttpStatusCode.OK, status)
            assertEquals(getUserWithRolesAsString(user.email!!, user.cn), bodyAsText())
        }
    }

    @Test
    fun testReadOnlyAdminGetUser() = testSuspend {
        testClient.get("/get-user?userCn=${user.cn}") {
            headers {
                append("Authorization", "Bearer ${readOnlyAdminSession.authToken}")
                append("Delta-Client", "${client.clientId}:${client.clientSecret}")
            }
        }.apply {
            assertEquals(HttpStatusCode.OK, status)
            assertEquals(getUserWithRolesAsString(user.email!!, user.cn), bodyAsText())
        }
    }

    @Test
    fun testNonAdminGetUser() = testSuspend {
        Assert.assertThrows(ApiError::class.java) {
            runBlocking {
                testClient.get("/get-user?userCn=${user.cn}") {
                    headers {
                        append("Authorization", "Bearer ${userSession.authToken}")
                        append("Delta-Client", "${client.clientId}:${client.clientSecret}")
                    }
                }
            }
        }.apply {
            assertEquals("forbidden", errorCode)
        }
    }

    @Test
    fun testAdminGetNonExistentUser() = testSuspend {
        testClient.get("/get-user?userCn=${NON_EXISTENT_USER_CN}") {
            headers {
                append("Authorization", "Bearer ${adminSession.authToken}")
                append("Delta-Client", "${client.clientId}:${client.clientSecret}")
            }
        }.apply {
            assertEquals(HttpStatusCode.NotFound, status)
            assertEquals("User not found", bodyAsText())
        }
    }

    @Before
    fun resetMocks() {
        clearAllMocks()
        coEvery { oauthSessionService.retrieveFomAuthToken(adminSession.authToken, client) } answers { adminSession }
        coEvery {
            oauthSessionService.retrieveFomAuthToken(readOnlyAdminSession.authToken, client)
        } answers { readOnlyAdminSession }
        coEvery { oauthSessionService.retrieveFomAuthToken(userSession.authToken, client) } answers { userSession }
        val organisations = listOf(
            OrganisationNameAndCode("orgCode1", "Organisation Name 1"),
            OrganisationNameAndCode("orgCode2", "Organisation Name 2"),
            OrganisationNameAndCode("orgCode3", "Organisation Name 3"),
        )
        val accessGroups = listOf(
            AccessGroup("access-group-1", null, null, true, false),
            AccessGroup("access-group-2", "statistics", null, true, false),
            AccessGroup("access-group-3", null, null, true, false),
        )
        mockUserLookupService(
            userLookupService,
            listOf(adminUser, readOnlyAdminUser, regularUser, user),
            organisations, accessGroups
        )
    }

    companion object {
        private lateinit var testApp: TestApplication
        private lateinit var testClient: HttpClient
        private lateinit var controller: AdminGetUserController

        private val oauthSessionService = mockk<OAuthSessionService>()

        private val userLookupService = mockk<UserLookupService>()

        private val client = testServiceClient()
        private val adminUser = testLdapUser(cn = "admin", memberOfCNs = listOf(DeltaConfig.DATAMART_DELTA_ADMIN))
        private val readOnlyAdminUser =
            testLdapUser(cn = "read-only-admin", memberOfCNs = listOf(DeltaSystemRole.READ_ONLY_ADMIN.adCn()))
        private val regularUser = testLdapUser(cn = "user", memberOfCNs = emptyList())

        private val adminSession = OAuthSession(1, adminUser.cn, client, "adminToken", Instant.now(), "trace", false)
        private val readOnlyAdminSession =
            OAuthSession(1, readOnlyAdminUser.cn, client, "readOnlyAdminToken", Instant.now(), "trace", false)
        private val userSession = OAuthSession(1, regularUser.cn, client, "userToken", Instant.now(), "trace", false)

        private val user = testLdapUser(
            cn = "beingUpdated!user.com",
            email = "beingUpdated@user.com",
            memberOfCNs = listOf(
                DeltaConfig.DATAMART_DELTA_USER,
                "datamart-delta-user-orgCode1",
                "datamart-delta-user-orgCode2",
                "datamart-delta-access-group-2",
                "datamart-delta-access-group-3",
                "datamart-delta-access-group-2-orgCode2",
                "datamart-delta-access-group-3-orgCode1",
                "datamart-delta-delegate-access-group-3",
                "datamart-delta-role-1",
                "datamart-delta-role-1-orgCode1",
                "datamart-delta-role-1-orgCode2",
            ),
            mobile = "0123456789",
            telephone = "0987654321",
        )
        private const val NON_EXISTENT_USER_CN = "fake!user.com"

        private fun getUserWithRolesAsString(email: String, cn: String): String {
            return "{" +
                        "\"user\":{" +
                            "\"dn\":\"dn\"," +
                            "\"cn\":\"$cn\"," +
                            "\"memberOfCNs\":[" +
                                "\"datamart-delta-user\"," +
                                "\"datamart-delta-user-orgCode1\"," +
                                "\"datamart-delta-user-orgCode2\"," +
                                "\"datamart-delta-access-group-2\"," +
                                "\"datamart-delta-access-group-3\"," +
                                "\"datamart-delta-access-group-2-orgCode2\"," +
                                "\"datamart-delta-access-group-3-orgCode1\"," +
                                "\"datamart-delta-delegate-access-group-3\"," +
                                "\"datamart-delta-role-1\"," +
                                "\"datamart-delta-role-1-orgCode1\"," +
                                "\"datamart-delta-role-1-orgCode2\"" +
                            "]," +
                            "\"email\":\"$email\"," +
                            "\"deltaTOTPSecret\":null," +
                            "\"firstName\":\"Test\"," +
                            "\"lastName\":\"Surname\"," +
                            "\"fullName\":\"Test Surname\"," +
                            "\"accountEnabled\":true," +
                            "\"mangledDeltaObjectGuid\":\"mangled-id\"," +
                            "\"javaUUIDObjectGuid\":null," +
                            "\"telephone\":\"0987654321\"," +
                            "\"mobile\":\"0123456789\"," +
                            "\"positionInOrganisation\":null," +
                            "\"reasonForAccess\":null," +
                            "\"comment\":null," +
                            "\"notificationStatus\":\"active\"" +
                        "}," +
                        "\"roles\":{" +
                            "\"systemRoles\":[{\"name\":\"user\",\"organisationIds\":[\"orgCode1\",\"orgCode2\"]}]," +
                            "\"externalRoles\":[]," +
                            "\"accessGroups\":[" +
                                "{\"name\":\"access-group-2\"," +
                                    "\"displayName\":null," +
                                    "\"classification\":\"statistics\"," +
                                    "\"organisationIds\":[\"orgCode2\"]," +
                                    "\"isDelegate\":false" +
                                "}," +
                                "{\"name\":\"access-group-3\"," +
                                    "\"displayName\":null," +
                                    "\"classification\":null," +
                                    "\"organisationIds\":[\"orgCode1\"]," +
                                    "\"isDelegate\":true" +
                                "}" +
                            "]," +
                            "\"organisations\":[" +
                                "{\"code\":\"orgCode1\",\"name\":\"Organisation Name 1\"}," +
                                "{\"code\":\"orgCode2\",\"name\":\"Organisation Name 2\"}" +
                            "]" +
                        "}" +
                    "}"
        }

        @BeforeClass
        @JvmStatic
        fun setup() {
            controller = AdminGetUserController(
                userLookupService,
            )

            testApp = TestApplication {
                application {
                    configureSerialization()
                    authentication {
                        bearer(OAUTH_ACCESS_BEARER_TOKEN_AUTH_NAME) {
                            realm = "auth-service"
                            authenticate { oauthSessionService.retrieveFomAuthToken(it.token, client) }
                        }
                        clientHeaderAuth(CLIENT_HEADER_AUTH_NAME) {
                            headerName = "Delta-Client"
                            clients = listOf(testServiceClient())
                        }
                    }
                    routing {
                        withBearerTokenAuth {
                            route("/get-user") {
                                controller.route(this)
                            }
                        }
                    }
                }
            }

            testClient = testApp.createClient {
                install(ContentNegotiation) {
                    json()
                }
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
