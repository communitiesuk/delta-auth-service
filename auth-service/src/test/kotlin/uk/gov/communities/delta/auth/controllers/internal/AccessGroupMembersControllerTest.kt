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
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import org.junit.*
import org.junit.Assert.assertThrows
import uk.gov.communities.delta.auth.config.DeltaConfig
import uk.gov.communities.delta.auth.config.LDAPConfig
import uk.gov.communities.delta.auth.controllers.internal.AccessGroupMembersController.AccessGroupMembersRequest
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
import javax.naming.NamingEnumeration
import javax.naming.directory.*
import javax.naming.directory.Attributes
import javax.naming.ldap.InitialLdapContext
import kotlin.test.assertEquals


class AccessGroupMembersControllerTest {

    @Test
    fun testGetAccessGroupMembersEmptyAccessGroupName() {
        val mockAccessGroupMembersRequest = AccessGroupMembersRequest("", "test-org-id")

        assertThrows(ApiError::class.java) {
            runBlocking {
                testClient.get("/access-group-members") {
                    headers {
                        append("Authorization", "Bearer ${internalUserSession.authToken}")
                        append("Delta-Client", "${client.clientId}:${client.clientSecret}")
                    }
                    contentType(ContentType.Application.Json)
                    setBody(Json.encodeToString(mockAccessGroupMembersRequest))
                }
            }
        }.apply {
            assertEquals(HttpStatusCode.BadRequest, this.statusCode)
            assertEquals("no_access_group_name", this.errorCode)
            assertEquals("Access group name is missing in request", this.errorDescription)
        }
    }


    @Test
    fun testGetAccessGroupMembersEmptyOrganisationId() {
        val mockAccessGroupMembersRequest = AccessGroupMembersRequest("test-group-name", "")

        assertThrows(ApiError::class.java) {
            runBlocking {
                testClient.get("/access-group-members") {
                    headers {
                        append("Authorization", "Bearer ${internalUserSession.authToken}")
                        append("Delta-Client", "${client.clientId}:${client.clientSecret}")
                    }
                    contentType(ContentType.Application.Json)
                    setBody(Json.encodeToString(mockAccessGroupMembersRequest))
                }
            }
        }.apply {
            assertEquals(HttpStatusCode.BadRequest, this.statusCode)
            assertEquals("no_organisation_id", this.errorCode)
            assertEquals("Organisation ID is missing in request", this.errorDescription)
        }
    }


    @Test
    fun testUserCanRetrieveAccessGroupMembers() = testSuspend {
        val mockAccessGroupMembersRequest = AccessGroupMembersRequest("test-group-name", "test-org-id")

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
            contentType(ContentType.Application.Json)
            setBody(Json.encodeToString(mockAccessGroupMembersRequest))
        }.apply {
            assertEquals(HttpStatusCode.OK, status)

            val returnedUsers = Json.decodeFromString<List<LdapRepository.UserWithRoles>>(bodyAsText())

            assertEquals(mockUsers.size, returnedUsers.size)
            assertEquals(mockUsers, returnedUsers)

            coVerify(exactly = 1) {
                ldapRepository.getUsersForOrgAccessGroupWithRoles(mockAccessGroupMembersRequest.accessGroupName, mockAccessGroupMembersRequest.organisationId)
            }
            confirmVerified(ldapRepository)
        }
    }


    @Test
    fun testInactiveUsersFilteredFromGetUsersForOrgAccessGroupWithRoles() {
        val mockLdapConfig = mockk<LDAPConfig>()
        every { mockLdapConfig.authServiceUserDn } returns "mockedUserDn"
        every { mockLdapConfig.authServiceUserPassword } returns "mockedPassword"
        every { mockLdapConfig.userContainerDn } returns "mockedUserContainerDn"
        every { mockLdapConfig.accessGroupContainerDn } returns "mockedGroupContainerDn"
        every { mockLdapConfig.deltaUserDnFormat } returns "CN=%s,OU=users"
        every { mockLdapConfig.groupDnFormat } returns "CN=%s,OU=groups"

        val objectGUIDMode = LdapRepository.ObjectGUIDMode.NEW_JAVA_UUID_STRING
        val ldapRepository = LdapRepository(mockLdapConfig, objectGUIDMode)

        val mockResult1 = mockk<SearchResult>()
        val mockResult2 = mockk<SearchResult>()
        val mockAttrs1 = mockk<Attributes>()
        val mockAttrs2 = mockk<Attributes>()

        every { mockResult1.attributes } returns mockAttrs1
        every { mockAttrs1.get("userAccountControl")?.get() } returns "514"
        every { mockAttrs1.get("memberOf")?.all?.toList() } returns emptyList<String>()

        every { mockResult2.attributes } returns mockAttrs2
        every { mockAttrs2.get("userAccountControl")?.get() } returns "512"
        every { mockAttrs2.get("memberOf")?.all?.toList() } returns listOf("CN=datamart-delta-user-test")

        val mockResults = mockk<NamingEnumeration<SearchResult>>()
        every { mockResults.hasMore() } returnsMany listOf(true, true, false)
        every { mockResults.next() } returnsMany listOf(mockResult1, mockResult2)

        val mockCtx = mockk<InitialLdapContext>()
        every { mockCtx.search(any<String>(), any<String>(), any<SearchControls>()) } returns mockResults

        mockkObject(ldapRepository)
        every { ldapRepository.bind(any(), any()) } returns mockCtx

        every { mockCtx.close() } just Runs

        val result = ldapRepository.getUsersForOrgAccessGroupWithRoles("someGroupName", "someOrganisationId")

        //assert(result.isEmpty())
        assert(result.size == 1)
    }


    @Test
    fun testActiveUsersFilteredFromGetUsersForOrgAccessGroupWithRoles() {
        val mockLdapConfig = mockk<LDAPConfig>()
        every { mockLdapConfig.authServiceUserDn } returns "mockedUserDn"
        every { mockLdapConfig.authServiceUserPassword } returns "mockedPassword"
        every { mockLdapConfig.userContainerDn } returns "mockedUserContainerDn"
        every { mockLdapConfig.accessGroupContainerDn } returns "mockedGroupContainerDn"
        every { mockLdapConfig.deltaUserDnFormat } returns "CN=%s,OU=users"
        every { mockLdapConfig.groupDnFormat } returns "CN=%s,OU=groups"
        every { mockLdapConfig.deltaLdapUrl } returns "ldap://mocked.url"

        val objectGUIDMode = LdapRepository.ObjectGUIDMode.NEW_JAVA_UUID_STRING
        val ldapRepository = LdapRepository(mockLdapConfig, objectGUIDMode)

        // Mock the active user
        val mockResult1 = mockk<SearchResult>()
        val mockAttrs1 = mockk<Attributes>()
        every { mockResult1.attributes } returns mockAttrs1
        every { mockAttrs1.get("userAccountControl")?.get() } returns "512"  // Active account
        every { mockAttrs1.get("mail")?.get() } returns "active.user@example.com"
        every { mockAttrs1.get("memberOf")?.all?.toList() } returns listOf("CN=datamart-delta-user-org-pw-dst")

        // Mock the inactive user
        val mockResult2 = mockk<SearchResult>()
        val mockAttrs2 = mockk<Attributes>()
        every { mockResult2.attributes } returns mockAttrs2
        every { mockAttrs2.get("userAccountControl")?.get() } returns "514"  // Inactive account
        every { mockAttrs2.get("mail")?.get() } returns "inactive.user@example.com"
        every { mockAttrs2.get("memberOf")?.all?.toList() } returns listOf("CN=datamart-delta-user-org-pw-dst")

        val mockResults = mockk<NamingEnumeration<SearchResult>>()
        every { mockResults.hasMore() } returnsMany listOf(true, false)
        every { mockResults.next() } returnsMany listOf(mockResult1, mockResult2)

        val mockCtx = mockk<InitialLdapContext>()
        every { mockCtx.search(any<String>(), any<String>(), any<SearchControls>()) } returns mockResults
        every { mockCtx.close() } just Runs

        mockkObject(ldapRepository)
        every { ldapRepository.bind(any(), any()) } returns mockCtx

        println(mockResults.hasMore())  // Add these temporarily to debug
        println(mockResults.next())

        // Call the method being tested
        val result = ldapRepository.getUsersForOrgAccessGroupWithRoles("someGroupName", "someOrganisationId")

        // Assert that only the active user is returned
        assert(result.size == 1)
        assert(result.first().mail == "active.user@example.com")
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
