package uk.gov.communities.delta.controllers

import io.ktor.client.*
import io.ktor.client.plugins.contentnegotiation.*
import io.ktor.client.request.*
import io.ktor.http.*
import io.ktor.serialization.kotlinx.json.*
import io.ktor.server.auth.*
import io.ktor.server.routing.*
import io.ktor.server.testing.*
import io.ktor.test.dispatcher.*
import io.mockk.*
import kotlinx.coroutines.runBlocking
import org.junit.AfterClass
import org.junit.Assert
import org.junit.Before
import org.junit.BeforeClass
import uk.gov.communities.delta.auth.config.DeltaConfig
import uk.gov.communities.delta.auth.controllers.internal.EditRolesController
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

class EditRolesControllerTest {
    @Test
    fun testEditRolesForUser() = testSuspend {
        testClient.post("/roles") {
            headers {
                append("Authorization", "Bearer ${externalUserSession.authToken}")
                append("Delta-Client", "${client.clientId}:${client.clientSecret}")
            }
            contentType(ContentType.Application.Json)
            setBody("{\"addToRoles\": [\"data-providers\"], \"removeFromRoles\": [\"data-certifiers\"]}")
        }.apply {
            assertEquals(HttpStatusCode.OK, status)
            coVerify(exactly = 1) { groupService.addUserToGroup(externalUser.cn, externalUser.dn, "datamart-delta-data-providers", any(), null) }
            coVerify(exactly = 1) { groupService.addUserToGroup(externalUser.cn, externalUser.dn, "datamart-delta-data-providers-orgCode1", any(), null) }
            coVerify(exactly = 1) { groupService.addUserToGroup(externalUser.cn, externalUser.dn, "datamart-delta-data-providers-orgCode2", any(), null) }
            coVerify(exactly = 1) { groupService.removeUserFromGroup(externalUser.cn, externalUser.dn, "datamart-delta-data-certifiers", any(), null) }
            coVerify(exactly = 1) { groupService.removeUserFromGroup(externalUser.cn, externalUser.dn, "datamart-delta-data-certifiers-orgCode1", any(), null) }
            coVerify(exactly = 1) { groupService.removeUserFromGroup(externalUser.cn, externalUser.dn, "datamart-delta-data-certifiers-orgCode2", any(), null) }
            confirmVerified(groupService)
        }
    }

    @Test
    fun testExternalUserCannotRequestInternalRole() {
        Assert.assertThrows(ApiError::class.java) {
            runBlocking {
                testClient.post("/roles") {
                    headers {
                        append("Authorization", "Bearer ${externalUserSession.authToken}")
                        append("Delta-Client", "${client.clientId}:${client.clientSecret}")
                    }
                    contentType(ContentType.Application.Json)
                    setBody("{\"addToRoles\": [\"payments-reviewers\"], \"removeFromRoles\": []}")
                }
            }
        }.apply {
            assertEquals("illegal_role", errorCode)
            assertEquals(HttpStatusCode.Forbidden, statusCode)
            confirmVerified(groupService)
        }
    }

    @Test
    fun testInternalUserCanRequestInternalRole() = testSuspend {
        testClient.post("/roles") {
            headers {
                append("Authorization", "Bearer ${internalUserSession.authToken}")
                append("Delta-Client", "${client.clientId}:${client.clientSecret}")
            }
            contentType(ContentType.Application.Json)
            setBody("{\"addToRoles\": [\"payments-reviewers\"], \"removeFromRoles\": [\"data-certifiers\"]}")
        }.apply {
            assertEquals(HttpStatusCode.OK, status)
            coVerify(exactly = 1) { groupService.addUserToGroup(internalUser.cn, internalUser.dn, "datamart-delta-payments-reviewers", any(), null) }
            coVerify(exactly = 1) { groupService.addUserToGroup(internalUser.cn, internalUser.dn, "datamart-delta-payments-reviewers-orgCode1", any(), null) }
            coVerify(exactly = 1) { groupService.addUserToGroup(internalUser.cn, internalUser.dn, "datamart-delta-payments-reviewers-orgCode2", any(), null) }
            coVerify(exactly = 1) {
                groupService.removeUserFromGroup(
                    internalUser.cn,
                    internalUser.dn,
                    "datamart-delta-data-certifiers",
                    any(),
                    null
                )
            }
            coVerify(exactly = 1) {
                groupService.removeUserFromGroup(
                    internalUser.cn,
                    internalUser.dn,
                    "datamart-delta-data-certifiers-orgCode1",
                    any(),
                    null
                )
            }
            coVerify(exactly = 1) {
                groupService.removeUserFromGroup(
                    internalUser.cn,
                    internalUser.dn,
                    "datamart-delta-data-certifiers-orgCode2",
                    any(),
                    null
                )
            }
            confirmVerified(groupService)
        }
    }

    @Test
    fun testSendingCurrentRolesHasNoEffect() = testSuspend {
        testClient.post("/roles") {
            headers {
                append("Authorization", "Bearer ${internalUserSession.authToken}")
                append("Delta-Client", "${client.clientId}:${client.clientSecret}")
            }
            contentType(ContentType.Application.Json)
            setBody("{\"addToRoles\": [\"data-certifiers\"], \"removeFromRoles\": [\"data-providers\"]}")
        }.apply {
            assertEquals(HttpStatusCode.OK, status)
            confirmVerified(groupService)
        }
    }

    @Test
    fun testInternalUserCannotRemoveAdminRole() {
        Assert.assertThrows(ApiError::class.java) {
            runBlocking {
                testClient.post("/roles") {
                    headers {
                        append("Authorization", "Bearer ${internalUserSession.authToken}")
                        append("Delta-Client", "${client.clientId}:${client.clientSecret}")
                    }
                    contentType(ContentType.Application.Json)
                    setBody("{\"addToRoles\": [\"payments-reviewers\"], \"removeFromRoles\": [\"dataset-admins\"]}")
                }
            }
        }.apply {
            assertEquals("illegal_role", errorCode)
            assertEquals("illegal_role (403 Forbidden) Not permitted to remove role dataset-admins", message)
            assertEquals(HttpStatusCode.Forbidden, statusCode)
            confirmVerified(groupService)
        }
    }

    @Before
    fun resetMocks() {
        clearAllMocks()
        coEvery { oauthSessionService.retrieveFomAuthToken(externalUserSession.authToken, client) } answers { externalUserSession }
        coEvery { oauthSessionService.retrieveFomAuthToken(internalUserSession.authToken, client) } answers { internalUserSession }
        mockUserLookupService(userLookupService, listOf(internalUser, externalUser), organisations, accessGroups)
        coEvery { groupService.addUserToGroup(externalUser.cn, externalUser.dn, any(), any(), null)} just runs
        coEvery { groupService.removeUserFromGroup(externalUser.cn, externalUser.dn, any(), any(), null)} just runs
        coEvery { groupService.addUserToGroup(internalUser.cn, externalUser.dn, any(), any(), null)} just runs
        coEvery { groupService.removeUserFromGroup(internalUser.cn, externalUser.dn, any(), any(), null)} just runs
    }

    companion object {
        private lateinit var testApp: TestApplication
        private lateinit var testClient: HttpClient
        private lateinit var controller: EditRolesController

        private val oauthSessionService = mockk<OAuthSessionService>()

        private val userLookupService = mockk<UserLookupService>()
        private val groupService = mockk<GroupService>()

        private val organisations = listOf(
            OrganisationNameAndCode("orgCode1", "Organisation Name 1"),
            OrganisationNameAndCode("orgCode2", "Organisation Name 2"),
            OrganisationNameAndCode("orgCode3", "Organisation Name 3"),
        )

        @Suppress("BooleanLiteralArgument")
        private val accessGroups = listOf(
            AccessGroup("access-group-1", null, null, true, false),
            AccessGroup("access-group-2", "statistics", null, true, false),
            AccessGroup("access-group-3", null, null, true, false),
        )

        private val client = testServiceClient()

        private val externalUser = testLdapUser(
            cn = "external!user.com",
            email = "external@user.com",
            memberOfCNs = listOf(
                DeltaConfig.DATAMART_DELTA_USER,
                "datamart-delta-user-orgCode1",
                "datamart-delta-user-orgCode2",
                "datamart-delta-data-certifiers",
                "datamart-delta-data-certifiers-orgCode1",
                "datamart-delta-data-certifiers-orgCode2",
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

        private val internalUser = testLdapUser(
            cn = "internal!user.com",
            email = "internal@user.com",
            memberOfCNs = listOf(
                DeltaConfig.DATAMART_DELTA_USER,
                DeltaConfig.DATAMART_DELTA_INTERNAL_USER,
                "datamart-delta-user-orgCode1",
                "datamart-delta-user-orgCode2",
                "datamart-delta-data-certifiers",
                "datamart-delta-data-certifiers-orgCode1",
                "datamart-delta-data-certifiers-orgCode2",
                "datamart-delta-access-group-2",
                "datamart-delta-access-group-3",
                "datamart-delta-access-group-2-orgCode2",
                "datamart-delta-access-group-3-orgCode1",
                "datamart-delta-delegate-access-group-3",
                "datamart-delta-role-1",
                "datamart-delta-role-1-orgCode1",
                "datamart-delta-role-1-orgCode2",
                "datamart-delta-dataset-admins-1",
                "datamart-delta-dataset-admins-orgCode1",
            ),
            mobile = "0123456789",
            telephone = "0987654321",
        )

        private val externalUserSession = OAuthSession(1, externalUser.cn, client, "externalUserToken", Instant.now(), "trace", false)
        private val internalUserSession = OAuthSession(1, internalUser.cn, client, "internalUserToken", Instant.now(), "trace", false)

        @BeforeClass
        @JvmStatic
        fun setup() {
            controller = EditRolesController(
                userLookupService,
                groupService,
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
                            route("/roles") {
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
