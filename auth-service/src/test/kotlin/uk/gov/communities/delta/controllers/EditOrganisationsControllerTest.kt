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
import org.junit.*
import uk.gov.communities.delta.auth.config.DeltaConfig
import uk.gov.communities.delta.auth.controllers.internal.EditOrganisationsController
import uk.gov.communities.delta.auth.plugins.ApiError
import uk.gov.communities.delta.auth.plugins.configureSerialization
import uk.gov.communities.delta.auth.security.CLIENT_HEADER_AUTH_NAME
import uk.gov.communities.delta.auth.security.OAUTH_ACCESS_BEARER_TOKEN_AUTH_NAME
import uk.gov.communities.delta.auth.security.clientHeaderAuth
import uk.gov.communities.delta.auth.services.*
import uk.gov.communities.delta.auth.withBearerTokenAuth
import uk.gov.communities.delta.helper.testLdapUser
import uk.gov.communities.delta.helper.testServiceClient
import java.time.Instant
import kotlin.test.assertEquals

class EditOrganisationsControllerTest {
    @Test
    fun userCanUpdateOrganisations() = testSuspend {
        testClient.post("/organisations") {
            headers {
                append("Authorization", "Bearer ${testUserSession.authToken}")
                append("Delta-Client", "${client.clientId}:${client.clientSecret}")
            }
            contentType(ContentType.Application.Json)
            setBody("{\"userSelectedOrgs\": [\"orgCode1\", \"orgCode3\"]}")
        }.apply {
            assertEquals(HttpStatusCode.OK, status)
            coVerify(exactly = 1) {
                groupService.addUserToGroup(
                    testUser.cn,
                    testUser.dn,
                    "datamart-delta-user-orgCode3",
                    any(),
                    null
                )
                groupService.addUserToGroup(
                    testUser.cn,
                    testUser.dn,
                    "datamart-delta-data-certifiers-orgCode3",
                    any(),
                    null
                )
                groupService.removeUserFromGroup(
                    testUser.cn,
                    testUser.dn,
                    "datamart-delta-user-orgCode2",
                    any(),
                    null
                )
                groupService.removeUserFromGroup(
                    testUser.cn,
                    testUser.dn,
                    "datamart-delta-access-group-3-orgCode2",
                    any(),
                    null
                )
                groupService.removeUserFromGroup(
                    testUser.cn,
                    testUser.dn,
                    "datamart-delta-data-certifiers-orgCode2",
                    any(),
                    null
                )
            }
            confirmVerified(groupService)
        }
    }

    @Test
    fun userCannotRemoveAllOrganisations() = testSuspend {
        Assert.assertThrows(ApiError::class.java) {
            runBlocking {
                testClient.post("/organisations") {
                    headers {
                        append("Authorization", "Bearer ${testUserSession.authToken}")
                        append("Delta-Client", "${client.clientId}:${client.clientSecret}")
                    }
                    contentType(ContentType.Application.Json)
                    setBody("{\"userSelectedOrgs\": []}")
                }
            }
        }.apply {
            assertEquals("zero_organisations", errorCode)
            assertEquals(HttpStatusCode.Forbidden, statusCode)
            coVerify(exactly = 0) { groupService.addUserToGroup(any(), any(), any(), any(), any()) }
            coVerify(exactly = 0) { groupService.removeUserFromGroup(any(), any(), any(), any(), any()) }
            confirmVerified(groupService)
        }
    }

    @Test
    fun userCannotUpdateNonDomainOrganisations() = testSuspend {
        Assert.assertThrows(ApiError::class.java) {
            runBlocking {
                testClient.post("/organisations") {
                    headers {
                        append("Authorization", "Bearer ${testUserSession.authToken}")
                        append("Delta-Client", "${client.clientId}:${client.clientSecret}")
                    }
                    contentType(ContentType.Application.Json)
                    setBody("{\"userSelectedOrgs\": [\"orgCode1\", \"orgCode2\", \"orgCode4\"]}")
                }
            }
        }.apply {
            assertEquals("non_domain_organisation", errorCode)
            assertEquals(HttpStatusCode.Forbidden, statusCode)
            coVerify(exactly = 0) { groupService.addUserToGroup(any(), any(), any(), any(), any()) }
            coVerify(exactly = 0) { groupService.removeUserFromGroup(any(), any(), any(), any(), any()) }
            confirmVerified(groupService)
        }
    }

    @Test
    fun addingAnOrganisationAddsOrgToAllRoles() = testSuspend {
        testClient.post("/organisations") {
            headers {
                append("Authorization", "Bearer ${testUserSession.authToken}")
                append("Delta-Client", "${client.clientId}:${client.clientSecret}")
            }
            contentType(ContentType.Application.Json)
            setBody("{\"userSelectedOrgs\": [\"orgCode1\", \"orgCode2\", \"orgCode3\"]}")
        }.apply {
            assertEquals(HttpStatusCode.OK, status)
            coVerify(exactly = 1) {
                groupService.addUserToGroup(
                    testUser.cn,
                    testUser.dn,
                    "datamart-delta-user-orgCode3",
                    any(),
                    null
                )
                groupService.addUserToGroup(
                    testUser.cn,
                    testUser.dn,
                    "datamart-delta-data-certifiers-orgCode3",
                    any(),
                    null
                )
            }
            confirmVerified(groupService)
        }
    }

    @Test
    fun removingAnOrganisationRemovesAllGroupsForThatOrg() = testSuspend {
        testClient.post("/organisations") {
            headers {
                append("Authorization", "Bearer ${testUserSession.authToken}")
                append("Delta-Client", "${client.clientId}:${client.clientSecret}")
            }
            contentType(ContentType.Application.Json)
            setBody("{\"userSelectedOrgs\": [\"orgCode1\"]}")
        }.apply {
            assertEquals(HttpStatusCode.OK, status)
            coVerify(exactly = 1) {
                groupService.removeUserFromGroup(
                    testUser.cn,
                    testUser.dn,
                    "datamart-delta-user-orgCode2",
                    any(),
                    null
                )
                groupService.removeUserFromGroup(
                    testUser.cn,
                    testUser.dn,
                    "datamart-delta-access-group-3-orgCode2",
                    any(),
                    null
                )
                groupService.removeUserFromGroup(
                    testUser.cn,
                    testUser.dn,
                    "datamart-delta-data-certifiers-orgCode2",
                    any(),
                    null
                )
            }
            confirmVerified(groupService)
        }
    }

    @Before
    fun resetMocks() {
        clearAllMocks()
        coEvery {
            oauthSessionService.retrieveFomAuthToken(
                testUserSession.authToken,
                client
            )
        } answers { testUserSession }
        coEvery { userLookupService.lookupUserByCn(testUser.cn) } returns testUser
        coEvery { organisationService.findAllNamesAndCodes() } returns listOf(
            OrganisationNameAndCode("orgCode1", "Organisation Name 1"),
            OrganisationNameAndCode("orgCode2", "Organisation Name 2"),
            OrganisationNameAndCode("orgCode3", "Organisation Name 3"),
        )
        coEvery { accessGroupsService.getAllAccessGroups() } returns listOf(
            AccessGroup("access-group-1", null, null, true, true),
            AccessGroup("access-group-2", null, null, true, false),
            AccessGroup("access-group-3", null, null, false, true),
        )
        coEvery { organisationService.findAllByDomain(testUser.email!!) } returns listOf(
            Organisation("orgCode1", "Organisation Name 1"),
            Organisation("orgCode2", "Organisation Name 2"),
            Organisation("orgCode3", "Organisation Name 3"),
        )
        coEvery { groupService.addUserToGroup(testUser.cn, testUser.dn, any(), any(), null) } just runs
        coEvery { groupService.removeUserFromGroup(testUser.cn, testUser.dn, any(), any(), null) } just runs
    }

    companion object {
        private lateinit var testApp: TestApplication
        private lateinit var testClient: HttpClient
        private lateinit var controller: EditOrganisationsController

        private val oauthSessionService = mockk<OAuthSessionService>()

        private val userLookupService = mockk<UserLookupService>()
        private val groupService = mockk<GroupService>()
        private val organisationService = mockk<OrganisationService>()
        private val accessGroupsService = mockk<AccessGroupsService>()
        private val memberOfToDeltaRolesMapper = ::MemberOfToDeltaRolesMapper

        private val client = testServiceClient()

        private val testUser = testLdapUser(
            cn = "test!user.com",
            email = "test@user.com",
            memberOfCNs = listOf(
                DeltaConfig.DATAMART_DELTA_USER,
                "datamart-delta-user-orgCode1",
                "datamart-delta-user-orgCode2",
                "datamart-delta-data-certifiers",
                "datamart-delta-data-certifiers-orgCode1",
                "datamart-delta-data-certifiers-orgCode2",
                "datamart-delta-access-group-1",
                "datamart-delta-access-group-1-orgCode1",
                "datamart-delta-access-group-2",
                "datamart-delta-access-group-2-orgCode1",
                "datamart-delta-access-group-3",
                "datamart-delta-access-group-3-orgCode2",
            ),
            mobile = "0123456789",
            telephone = "0987654321",
        )

        private val testUserSession =
            OAuthSession(1, testUser.cn, client, "testUserToken", Instant.now(), "trace", false)

        @BeforeClass
        @JvmStatic
        fun setup() {
            controller = EditOrganisationsController(
                userLookupService,
                groupService,
                organisationService,
                accessGroupsService,
                memberOfToDeltaRolesMapper,
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
                            route("/organisations") {
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
