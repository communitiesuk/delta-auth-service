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
import kotlinx.serialization.json.Json
import org.junit.AfterClass
import org.junit.Assert
import org.junit.Before
import org.junit.BeforeClass
import uk.gov.communities.delta.auth.bearerTokenRoutes
import uk.gov.communities.delta.auth.config.DeltaConfig
import uk.gov.communities.delta.auth.controllers.internal.EditRolesController
import uk.gov.communities.delta.auth.plugins.ApiError
import uk.gov.communities.delta.auth.plugins.configureSerialization
import uk.gov.communities.delta.auth.security.CLIENT_HEADER_AUTH_NAME
import uk.gov.communities.delta.auth.security.OAUTH_ACCESS_BEARER_TOKEN_AUTH_NAME
import uk.gov.communities.delta.auth.security.clientHeaderAuth
import uk.gov.communities.delta.auth.services.*
import uk.gov.communities.delta.helper.testLdapUser
import uk.gov.communities.delta.helper.testServiceClient
import java.time.Instant
import kotlin.test.Test
import kotlin.test.assertEquals

class EditRolesControllerTest {
    @Test
    fun testEditRolesForUser() = testSuspend {
        testClient.post("/bearer/roles") {
            headers {
                append("Authorization", "Bearer ${externalUserSession.authToken}")
                append("Delta-Client", "${client.clientId}:${client.clientSecret}")
            }
            contentType(ContentType.Application.Json)
            setBody(Json.parseToJsonElement("{\"roles\": [\"data-providers\"]}"))
        }.apply {
            assertEquals(HttpStatusCode.OK, status)
            coVerify(exactly = 1) { groupService.addUserToGroup(externalUser.cn, externalUser.dn, "datamart-delta-data-providers", any(), null) }
            coVerify(exactly = 1) { groupService.addUserToGroup(externalUser.cn, externalUser.dn, "datamart-delta-data-providers-orgCode1", any(), null) }
            coVerify(exactly = 1) { groupService.addUserToGroup(externalUser.cn, externalUser.dn, "datamart-delta-data-providers-orgCode2", any(), null) }
            coVerify(exactly = 1) { groupService.removeUserFromGroup(externalUser.cn, externalUser.dn, "datamart-delta-data-certifiers", any(), null) }
            coVerify(exactly = 1) { groupService.removeUserFromGroup(externalUser.cn, externalUser.dn, "datamart-delta-data-certifiers-orgCode1", any(), null) }
            coVerify(exactly = 1) { groupService.removeUserFromGroup(externalUser.cn, externalUser.dn, "datamart-delta-data-certifiers-orgCode2", any(), null) }
        }
    }

    @Test
    fun testExternalUserCannotRequestInternalRole() = testSuspend {
        Assert.assertThrows(ApiError::class.java) {
            runBlocking {
                testClient.post("/bearer/roles") {
                    headers {
                        append("Authorization", "Bearer ${externalUserSession.authToken}")
                        append("Delta-Client", "${client.clientId}:${client.clientSecret}")
                    }
                    contentType(ContentType.Application.Json)
                    setBody(Json.parseToJsonElement("{\"roles\": [\"payments-reviewers\"]}"))
            }
            }.apply {
                assertEquals(HttpStatusCode.Forbidden, status)
                coVerify(exactly = 0) { groupService.addUserToGroup(any(), any(), any(), any(), any()) }
                coVerify(exactly = 0) { groupService.removeUserFromGroup(any(), any(), any(), any(), any()) }
            }
        }.apply {
            assertEquals("illegal_role", errorCode)
        }
    }

    @Test
    fun testInternalUserCanRequestInternalRole() = testSuspend {
        testClient.post("/bearer/roles") {
            headers {
                append("Authorization", "Bearer ${internalUserSession.authToken}")
                append("Delta-Client", "${client.clientId}:${client.clientSecret}")
            }
            contentType(ContentType.Application.Json)
            setBody(Json.parseToJsonElement("{\"roles\": [\"payments-reviewers\"]}"))
        }.apply {
            assertEquals(HttpStatusCode.OK, status)
            coVerify(exactly = 1) { groupService.addUserToGroup(internalUser.cn, internalUser.dn, "datamart-delta-payments-reviewers", any(), null) }
            coVerify(exactly = 1) { groupService.addUserToGroup(internalUser.cn, internalUser.dn, "datamart-delta-payments-reviewers-orgCode1", any(), null) }
            coVerify(exactly = 1) { groupService.addUserToGroup(internalUser.cn, internalUser.dn, "datamart-delta-payments-reviewers-orgCode2", any(), null) }
            coVerify(exactly = 1) { groupService.removeUserFromGroup(internalUser.cn, internalUser.dn, "datamart-delta-data-certifiers", any(), null) }
            coVerify(exactly = 1) { groupService.removeUserFromGroup(internalUser.cn, internalUser.dn, "datamart-delta-data-certifiers-orgCode1", any(), null) }
            coVerify(exactly = 1) { groupService.removeUserFromGroup(internalUser.cn, internalUser.dn, "datamart-delta-data-certifiers-orgCode2", any(), null) }
        }
    }

    @Before
    fun resetMocks() {
        clearAllMocks()
        coEvery { oauthSessionService.retrieveFomAuthToken(externalUserSession.authToken, client) } answers { externalUserSession }
        coEvery { oauthSessionService.retrieveFomAuthToken(internalUserSession.authToken, client) } answers { internalUserSession }
        coEvery { userLookupService.lookupUserByCn(externalUser.cn) } returns externalUser
        coEvery { userLookupService.lookupUserByCn(internalUser.cn) } returns internalUser
        coEvery { organisationService.findAllNamesAndCodes() } returns listOf(
            OrganisationNameAndCode("orgCode1", "Organisation Name 1"),
            OrganisationNameAndCode("orgCode2", "Organisation Name 2"),
            OrganisationNameAndCode("orgCode3", "Organisation Name 3"),
        )
        coEvery { accessGroupsService.getAllAccessGroups() } returns listOf(
            AccessGroup("access-group-1", null, null, true, false),
            AccessGroup("access-group-2", "statistics", null, true, false),
            AccessGroup("access-group-3", null, null, true, false),
        )
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
        private val organisationService = mockk<OrganisationService>()
        private val accessGroupsService = mockk<AccessGroupsService>()
        private val memberOfToDeltaRolesMapper = ::MemberOfToDeltaRolesMapper

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
                        bearerTokenRoutes(
                            mockk(relaxed = true),
                            mockk(relaxed = true),
                            mockk(relaxed = true),
                            mockk(relaxed = true),
                            mockk(relaxed = true),
                            mockk(relaxed = true),
                            controller,
                        )
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
