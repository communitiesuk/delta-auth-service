package uk.gov.communities.delta.auth.controllers.internal

import io.ktor.client.*
import io.ktor.client.plugins.contentnegotiation.*
import io.ktor.client.request.*
import io.ktor.client.request.headers
import io.ktor.client.statement.*
import io.ktor.http.*
import io.ktor.serialization.kotlinx.json.*
import io.ktor.server.application.*
import io.ktor.server.auth.*
import io.ktor.server.routing.*
import io.ktor.server.testing.*
import io.ktor.test.dispatcher.*
import io.mockk.*
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.Json
import org.junit.*
import org.junit.Assert.assertThrows
import uk.gov.communities.delta.auth.config.DeltaConfig
import uk.gov.communities.delta.auth.plugins.ApiError
import uk.gov.communities.delta.auth.plugins.configureSerialization
import uk.gov.communities.delta.auth.repositories.LdapRepository
import uk.gov.communities.delta.auth.security.CLIENT_HEADER_AUTH_NAME
import uk.gov.communities.delta.auth.security.OAUTH_ACCESS_BEARER_TOKEN_AUTH_NAME
import uk.gov.communities.delta.auth.security.clientHeaderAuth
import uk.gov.communities.delta.auth.services.*
import uk.gov.communities.delta.auth.withBearerTokenAuth
import uk.gov.communities.delta.helper.mockUserLookupService
import uk.gov.communities.delta.helper.testLdapUser
import uk.gov.communities.delta.helper.testServiceClient
import java.time.Instant
import kotlin.test.assertEquals
import org.junit.Test


class AccessGroupMembersControllerTest {

    @Test
    fun `getAccessGroupMembers - missing accessGroupName`() {

        assertThrows(ApiError::class.java) {
            runBlocking {
                testClient.get("/access-group-members") {
                    headers {
                        append("Authorization", "Bearer ${internalUserSession.authToken}")
                        append("Delta-Client", "${client.clientId}:${client.clientSecret}")
                    }
                    parameter("organisationId", "dluhc")
                    parameter("accessGroupName", null)
                }
            }
        }.apply {
            assertEquals(HttpStatusCode.BadRequest, this.statusCode)
            assertEquals("no_access_group_name", this.errorCode)
            assertEquals("Access group name is missing in request", this.errorDescription)
        }
    }


    @Test
    fun `getAccessGroupMembers - missing organisationId`() {

        assertThrows(ApiError::class.java) {
            runBlocking {
                testClient.get("/access-group-members") {
                    headers {
                        append("Authorization", "Bearer ${internalUserSession.authToken}")
                        append("Delta-Client", "${client.clientId}:${client.clientSecret}")
                    }
                    parameter("organisationId", null)
                    parameter("accessGroupName", "central-list")
                }
            }
        }.apply {
            assertEquals(HttpStatusCode.BadRequest, this.statusCode)
            assertEquals("no_organisation_id", this.errorCode)
            assertEquals("Organisation ID is missing in request", this.errorDescription)
        }
    }


    @Test
    fun `getAccessGroupMembers - returns list of users`() = testSuspend {
        val accessGroupName = "central-list"
        val organisationId = "dluhc"

        val mockUsers = listOf(
            LdapRepository.UserWithRoles(
                cn = "User1",
                objectGUID = "guid1",
                mail = "user1@example.com",
                fullName = "User One",
                roles = listOf("Data provider")
            ),
            LdapRepository.UserWithRoles(
                cn = "User2",
                objectGUID = "guid2",
                mail = "user2@example.com",
                fullName = "User Two",
                roles = listOf("Data certifier")
            )
        )

        every { ldapRepository.getUsersForOrgAccessGroupWithRoles(any(), any()) } returns mockUsers
        every { accessGroupsService.checkAccessGroupNameIsValid(any()) } just Runs
        every { accessGroupsService.checkAccessGroupPrefixIsValid(any()) } just Runs

        testClient.get("/access-group-members") {
            headers {
                append("Authorization", "Bearer ${externalUserSession.authToken}")
                append("Delta-Client", "${client.clientId}:${client.clientSecret}")
            }
            parameter("organisationId", organisationId)
            parameter("accessGroupName", accessGroupName)
        }.apply {
            assertEquals(HttpStatusCode.OK, status)

            val returnedUsers = Json.decodeFromString<List<LdapRepository.UserWithRoles>>(bodyAsText())

            assertEquals(mockUsers.size, returnedUsers.size)
            assertEquals(mockUsers, returnedUsers)
        }
    }


    @Before
    fun resetMocks() {
        clearAllMocks()
        coEvery {
            oauthSessionService.retrieveFromAuthToken(externalUserSession.authToken, client)
        } answers {externalUserSession }
        coEvery {
            oauthSessionService.retrieveFromAuthToken(
                internalUserSession.authToken,
                client
            )
        } answers { internalUserSession }
        coEvery { userGUIDMapService.getGUIDFromCN(
            externalUser.cn) } returns externalUser.getGUID()
        coEvery { userGUIDMapService.getGUIDFromCN(
            internalUser.cn) } returns internalUser.getGUID()
        coEvery { organisationService.findAllNamesAndCodes() } returns listOf(
            OrganisationNameAndCode("orgCode1", "Organisation Name 1"),
            OrganisationNameAndCode("orgCode2", "Organisation Name 2"),
            OrganisationNameAndCode("orgCode3", "Organisation Name 3"),
            OrganisationNameAndCode("orgCode4", "Organisation Name 4"),
            OrganisationNameAndCode("not-in-domain", "Organisation not in email domain"),
            OrganisationNameAndCode("dclg", "The Department"),
        )
        @Suppress("BooleanLiteralArgument")
        coEvery { accessGroupsService.getAllAccessGroups() } returns listOf(
            AccessGroup("access-group-1", null, "access group 1", true, true),
            AccessGroup("access-group-2", null, null, true, false),
            AccessGroup("access-group-3", null, "access group 3", false, true),
        )
        coEvery { organisationService.findAllByEmail(
            externalUser.email) } returns listOf(
            Organisation("orgCode1", "Organisation Name 1"),
            Organisation("orgCode2", "Organisation Name 2"),
            Organisation("orgCode3", "Organisation Name 3"),
            Organisation("orgCode4", "Organisation Name 4"),
        )
        coEvery {organisationService.findAllByEmail(
            internalUser.email) } returns listOf(
            Organisation("orgCode1", "Organisation Name 1"),
            Organisation("orgCode2", "Organisation Name 2"),
            Organisation("dclg", "The Department"),
        )
        mockUserLookupService(
            userLookupService,
            listOf(Pair(
                internalUser,
                internalUserSession
            ), Pair(
                externalUser,
                externalUserSession
            )),
            runBlocking { organisationService.findAllNamesAndCodes() },
            runBlocking { accessGroupsService.getAllAccessGroups() },
        )
        coEvery { groupService.addUserToGroup(externalUser, any(), any(), any()) } just runs
        coEvery { groupService.removeUserFromGroup(
            externalUser, any(), any(), any()) } just runs
        coEvery { groupService.addUserToGroup(internalUser, any(), any(), any()) } just runs
        coEvery { groupService.removeUserFromGroup(
            internalUser, any(), any(), any()) } just runs
        coEvery { userService.updateUser(externalUser, any(), any(), any()) } just runs
    }

    companion object {
        private lateinit var testApp: TestApplication
        private lateinit var testClient: HttpClient
        private lateinit var controller: AccessGroupMembersController

        private val oauthSessionService = mockk<OAuthSessionService>()

        private val userLookupService = mockk<UserLookupService>()
        private val userGUIDMapService = mockk<UserGUIDMapService>()
        private val ldapRepository = mockk<LdapRepository>()
        private val userService = mockk<UserService>()
        private val groupService = mockk<GroupService>()
        private val organisationService = mockk<OrganisationService>()
        private val accessGroupsService = mockk<AccessGroupsService>()

        private val client = testServiceClient()

        private val externalUser = testLdapUser(
            cn = "external!user.com",
            email = "external@user.com",
            memberOfCNs = listOf(
                DeltaConfig.DATAMART_DELTA_USER,
                "datamart-delta-user-orgCode1",
                "datamart-delta-user-orgCode2",
                "datamart-delta-user-orgCode3",
                "datamart-delta-access-group-1",
                "datamart-delta-access-group-1-orgCode1",
                "datamart-delta-access-group-1-orgCode3",
                "datamart-delta-access-group-2",
                "datamart-delta-access-group-2-orgCode1",
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
                "datamart-delta-access-group-3",
                "datamart-delta-access-group-3-orgCode1",
                "datamart-delta-delegate-access-group-3",
                "datamart-delta-role-1",
                "datamart-delta-role-1-orgCode1",
                "datamart-delta-role-1-orgCode2",
            ),
            mobile = "0123456789",
            telephone = "0987654321",
        )

        private val externalUserSession =
            OAuthSession(
                1,
                externalUser.cn,
                externalUser.getGUID(),
                client,
                "externalUserToken",
                Instant.now(),
                "trace",
                false
            )

        private val internalUserSession =
            OAuthSession(
                1,
                internalUser.cn,
                internalUser.getGUID(),
                client,
                "internalUserToken",
                Instant.now(),
                "trace",
                false
            )


        @BeforeClass
        @JvmStatic
        fun setup() {
            controller = AccessGroupMembersController(
                ldapRepository,
                accessGroupsService
            )

            testApp = TestApplication {
                application {
                    configureSerialization()
                    authentication {
                        bearer(OAUTH_ACCESS_BEARER_TOKEN_AUTH_NAME) {
                            realm = "auth-service"
                            authenticate { oauthSessionService.retrieveFromAuthToken(it.token, client) }
                        }
                        clientHeaderAuth(CLIENT_HEADER_AUTH_NAME) {
                            headerName = "Delta-Client"
                            clients = listOf(testServiceClient())
                        }
                    }
                    routing {
                        withBearerTokenAuth {
                            get("/access-group-members") {
                                controller.getAccessGroupMembers(call)
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
