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
import io.mockk.*
import junit.framework.TestCase.assertFalse
import junit.framework.TestCase.assertTrue
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement
import org.junit.AfterClass
import org.junit.Assert
import org.junit.Before
import org.junit.BeforeClass
import uk.gov.communities.delta.auth.config.DeltaConfig
import uk.gov.communities.delta.auth.controllers.internal.AdminEditUserController
import uk.gov.communities.delta.auth.controllers.internal.DeltaUserPermissionsRequestMapper
import uk.gov.communities.delta.auth.plugins.ApiError
import uk.gov.communities.delta.auth.plugins.NoUserException
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
import javax.naming.directory.DirContext
import javax.naming.directory.ModificationItem
import kotlin.test.Test
import kotlin.test.assertEquals

class AdminEditUserControllerTest {

    @Test
    fun testAdminUpdateUser() = testSuspend {
        coEvery {
            accessGroupDCLGMembershipUpdateEmailService.sendNotificationEmailsForChangeToUserAccessGroups(
                AccessGroupDCLGMembershipUpdateEmailService.UpdatedUser(user.email!!, user.fullName),
                adminUser, any(), any()
            )
        } just runs
        testClient.post("/edit-user?userCn=${user.cn}") {
            contentType(ContentType.Application.Json)
            setBody(getUserDetailsJson(user.email!!))
            headers {
                append("Authorization", "Bearer ${adminSession.authToken}")
                append("Delta-Client", "${client.clientId}:${client.clientSecret}")
            }
        }.apply {
            assertEquals(HttpStatusCode.OK, status)
            coVerify(exactly = 1) {
                userService.updateUser(user, capture(modifications), adminSession, any())
            }

            // Verify the correct changes are made to the user's details
            assertEquals(3, modifications.captured.size)
            assertTrue(modifications.captured.any { it.modificationOp == DirContext.REMOVE_ATTRIBUTE && it.attribute.id == "telephoneNumber" })
            assertTrue(modifications.captured.any { it.modificationOp == DirContext.ADD_ATTRIBUTE && it.attribute.id == "title" && it.attribute.get() == "test position" })
            assertTrue(modifications.captured.any { it.modificationOp == DirContext.REPLACE_ATTRIBUTE && it.attribute.id == "sn" && it.attribute.get() == "Surname Two" })
            assertFalse(modifications.captured.any { it.attribute.id == "comment" })
            assertFalse(modifications.captured.any { it.attribute.id == "givenName" })

            val expectedAddedGroups = arrayOf(
                "datamart-delta-user-orgCode3",
                "datamart-delta-access-group-1",
                "datamart-delta-delegate-access-group-2",
                "datamart-delta-access-group-2-orgCode3",
                "datamart-delta-data-providers-orgCode3",
                "datamart-delta-data-certifiers",
                "datamart-delta-data-certifiers-orgCode2",
                "datamart-delta-data-certifiers-orgCode3"
            )
            expectedAddedGroups.forEach {
                coVerify(exactly = 1) { groupService.addUserToGroup(user, it, any(), adminSession) }
            }
            coVerify(exactly = expectedAddedGroups.size) {
                groupService.addUserToGroup(user, any(), any(), adminSession)
            }

            val expectedRemovedGroups = arrayOf(
                "datamart-delta-user-orgCode1",
                "datamart-delta-access-group-3",
                "datamart-delta-access-group-3-orgCode1",
                "datamart-delta-delegate-access-group-3",
                "datamart-delta-data-providers-orgCode1"
            )
            expectedRemovedGroups.forEach {
                coVerify(exactly = 1) {
                    groupService.removeUserFromGroup(user, it, any(), adminSession)
                }
            }
            coVerify(exactly = expectedRemovedGroups.size) {
                groupService.removeUserFromGroup(user, any(), any(), adminSession)
            }
            coVerify(exactly = 1) {
                accessGroupDCLGMembershipUpdateEmailService.sendNotificationEmailsForChangeToUserAccessGroups(
                    AccessGroupDCLGMembershipUpdateEmailService.UpdatedUser(user), adminUser, any(), any()
                )
            }
            confirmVerified(userService, groupService, accessGroupDCLGMembershipUpdateEmailService)
        }
    }

    @Test
    fun testAdminUpdateUnchangedUser() = testSuspend {
        testClient.post("/edit-user?userCn=${unchangedUser.cn}") {
            contentType(ContentType.Application.Json)
            setBody(getUserDetailsJson(unchangedUser.email!!))
            headers {
                append("Authorization", "Bearer ${adminSession.authToken}")
                append("Delta-Client", "${client.clientId}:${client.clientSecret}")
            }
        }.apply {
            assertEquals(HttpStatusCode.OK, status)
            coVerify(exactly = 0) { userService.updateUser(any(), any(), any(), any()) }
            coVerify(exactly = 0) { userGUIDMapService.updateUserCN(any(), any())}
            coVerify(exactly = 0) { groupService.addUserToGroup(any(), any(), any(), any()) }
            coVerify(exactly = 0) { groupService.removeUserFromGroup(any(), any(), any(), any()) }
            assertEquals("{\"message\":\"No changes were made to the user\"}", bodyAsText())
        }
    }

    @Test
    fun testAdminUpdateUsernameChanged() = testSuspend {
        Assert.assertThrows(ApiError::class.java) {
            runBlocking {
                testClient.post("/edit-user?userCn=${user.cn}") {
                    contentType(ContentType.Application.Json)
                    setBody(getUserDetailsJson("fake@user.com"))
                    headers {
                        append("Authorization", "Bearer ${adminSession.authToken}")
                        append("Delta-Client", "${client.clientId}:${client.clientSecret}")
                    }
                }
            }
        }.apply {
            assertEquals("username_changed", errorCode)
            assertEquals(HttpStatusCode.BadRequest, statusCode)
            coVerify(exactly = 0) { userService.updateUser(any(), any(), any(), any()) }
            coVerify(exactly = 0) { userGUIDMapService.updateUserCN(any(), any())}
            coVerify(exactly = 0) { groupService.addUserToGroup(any(), any(), any(), any()) }
            coVerify(exactly = 0) { groupService.removeUserFromGroup(any(), any(), any(), any()) }
        }
    }

    @Test
    fun testAdminUpdateNonExistentUser() = testSuspend {
        Assert.assertThrows(ApiError::class.java) {
            runBlocking {
                testClient.post("/edit-user?userCn=$NON_EXISTENT_USER_CN") {
                    contentType(ContentType.Application.Json)
                    setBody(getUserDetailsJson(NON_EXISTENT_USER_EMAIL))
                    headers {
                        append("Authorization", "Bearer ${adminSession.authToken}")
                        append("Delta-Client", "${client.clientId}:${client.clientSecret}")
                    }
                }
            }
        }.apply {
            assertEquals("no_user", errorCode)
            assertEquals(HttpStatusCode.BadRequest, statusCode)
            coVerify(exactly = 0) { userService.updateUser(any(), any(), any(), any()) }
            coVerify(exactly = 0) { userGUIDMapService.updateUserCN(any(), any())}
            coVerify(exactly = 0) { groupService.addUserToGroup(any(), any(), any(), any()) }
            coVerify(exactly = 0) { groupService.removeUserFromGroup(any(), any(), any(), any()) }
        }
    }

    @Test
    fun testReadOnlyAdminUpdateUnchangedUser() = testSuspend {
        Assert.assertThrows(ApiError::class.java) {
            runBlocking {
                testClient.post("/edit-user?userCn=${user.cn}") {
                    contentType(ContentType.Application.Json)
                    setBody(getUserDetailsJson(user.email!!))
                    headers {
                        append("Authorization", "Bearer ${readOnlyAdminSession.authToken}")
                        append("Delta-Client", "${client.clientId}:${client.clientSecret}")
                    }
                }
            }
        }.apply {
            assertEquals("forbidden", errorCode)
            assertEquals(HttpStatusCode.Forbidden, statusCode)
            coVerify(exactly = 0) { userService.updateUser(any(), any(), any(), any()) }
            coVerify(exactly = 0) { userGUIDMapService.updateUserCN(any(), any())}
            coVerify(exactly = 0) { groupService.addUserToGroup(any(), any(), any(), any()) }
            coVerify(exactly = 0) { groupService.removeUserFromGroup(any(), any(), any(), any()) }
        }
    }

    @Test
    fun testNonAdminUpdateUnchangedUser() = testSuspend {
        Assert.assertThrows(ApiError::class.java) {
            runBlocking {
                testClient.post("/edit-user?userCn=${user.cn}") {
                    contentType(ContentType.Application.Json)
                    setBody(getUserDetailsJson(user.email!!))
                    headers {
                        append("Authorization", "Bearer ${regularUserSession.authToken}")
                        append("Delta-Client", "${client.clientId}:${client.clientSecret}")
                    }
                }
            }
        }.apply {
            assertEquals("forbidden", errorCode)
            assertEquals(HttpStatusCode.Forbidden, statusCode)
            coVerify(exactly = 0) { userService.updateUser(any(), any(), any(), any()) }
            coVerify(exactly = 0) { userGUIDMapService.updateUserCN(any(), any())}
            coVerify(exactly = 0) { groupService.addUserToGroup(any(), any(), any(), any()) }
            coVerify(exactly = 0) { groupService.removeUserFromGroup(any(), any(), any(), any()) }
        }
    }

    @Test
    fun testDisabledAdminUpdateUnchangedUser() = testSuspend {
        Assert.assertThrows(ApiError::class.java) {
            runBlocking {
                testClient.post("/edit-user?userCn=${user.cn}") {
                    contentType(ContentType.Application.Json)
                    setBody(getUserDetailsJson(user.email!!))
                    headers {
                        append("Authorization", "Bearer ${disabledAdminSession.authToken}")
                        append("Delta-Client", "${client.clientId}:${client.clientSecret}")
                    }
                }
            }
        }.apply {
            assertEquals("forbidden", errorCode)
            assertEquals(HttpStatusCode.Forbidden, statusCode)
            coVerify(exactly = 0) { userService.updateUser(any(), any(), any(), any()) }
            coVerify(exactly = 0) { userGUIDMapService.updateUserCN(any(), any())}
            coVerify(exactly = 0) { groupService.addUserToGroup(any(), any(), any(), any()) }
            coVerify(exactly = 0) { groupService.removeUserFromGroup(any(), any(), any(), any()) }
        }
    }

    @Before
    fun resetMocks() {
        modifications.clear()
        clearAllMocks()
        coEvery { oauthSessionService.retrieveFromAuthToken(adminSession.authToken, client) } answers { adminSession }
        coEvery {
            oauthSessionService.retrieveFromAuthToken(disabledAdminSession.authToken, client)
        } answers { disabledAdminSession }
        coEvery {
            oauthSessionService.retrieveFromAuthToken(readOnlyAdminSession.authToken, client)
        } answers { readOnlyAdminSession }
        coEvery {
            oauthSessionService.retrieveFromAuthToken(regularUserSession.authToken, client)
        } answers { regularUserSession }
        coEvery { organisationService.findAllNamesAndCodes() } returns organisations
        coEvery { accessGroupsService.getAllAccessGroups() } returns accessGroups
        mockUserLookupService(
            userLookupService,
            listOf(
                Pair(adminUser, adminSession),
                Pair(disabledAdminUser, disabledAdminSession),
                Pair(readOnlyAdminUser, readOnlyAdminSession),
                Pair(regularUser, regularUserSession),
                Pair(user, null),
                Pair(unchangedUser, null)
            ),
            runBlocking { organisationService.findAllNamesAndCodes() },
            runBlocking { accessGroupsService.getAllAccessGroups() }
        )
        coEvery { userGUIDMapService.getGUID(any()) } throws NoUserException("Test exception")
        coEvery { userGUIDMapService.getGUID(user.cn) } returns user.getGUID()
        coEvery { userGUIDMapService.getGUID(unchangedUser.cn) } returns unchangedUser.getGUID()
        coEvery { userService.updateUser(user, capture(modifications), adminSession, any()) } just runs
        coEvery { groupService.addUserToGroup(user, any(), any(), adminSession) } just runs
        coEvery { groupService.removeUserFromGroup(user, any(), any(), adminSession) } just runs
    }

    companion object {
        private lateinit var testApp: TestApplication
        private lateinit var testClient: HttpClient
        private lateinit var controller: AdminEditUserController

        private lateinit var oauthSessionService: OAuthSessionService
        private lateinit var userLookupService: UserLookupService
        private lateinit var userGUIDMapService: UserGUIDMapService
        private lateinit var userService: UserService
        private lateinit var groupService: GroupService
        private lateinit var organisationService: OrganisationService
        private lateinit var accessGroupsService: AccessGroupsService
        private lateinit var accessGroupDCLGMembershipUpdateEmailService: AccessGroupDCLGMembershipUpdateEmailService

        private val client = testServiceClient()
        private val adminUser = testLdapUser(cn = "admin", memberOfCNs = listOf(DeltaConfig.DATAMART_DELTA_ADMIN))
        private val disabledAdminUser =
            testLdapUser(
                cn = "disabledAdmin",
                memberOfCNs = listOf(DeltaConfig.DATAMART_DELTA_ADMIN),
                accountEnabled = false
            )
        private val readOnlyAdminUser =
            testLdapUser(cn = "read-only-admin", memberOfCNs = listOf(DeltaSystemRole.READ_ONLY_ADMIN.adCn()))
        private val regularUser = testLdapUser(cn = "user", memberOfCNs = emptyList())

        private val adminSession =
            OAuthSession(1, adminUser.cn, adminUser.getGUID(), client, "adminToken", Instant.now(), "trace", false)
        private val disabledAdminSession =
            OAuthSession(
                1,
                disabledAdminUser.cn,
                disabledAdminUser.getGUID(),
                client,
                "disabledAdminToken",
                Instant.now(),
                "trace",
                false
            )
        private val readOnlyAdminSession =
            OAuthSession(
                1,
                readOnlyAdminUser.cn,
                readOnlyAdminUser.getGUID(),
                client,
                "readOnlyAdminToken",
                Instant.now(),
                "trace",
                false
            )
        private val regularUserSession =
            OAuthSession(1, regularUser.cn, regularUser.getGUID(), client, "userToken", Instant.now(), "trace", false)

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
                "datamart-delta-data-providers",
                "datamart-delta-data-providers-orgCode1",
                "datamart-delta-data-providers-orgCode2",
            ),
            mobile = "0123456789",
            telephone = "0987654321",
        )

        private val unchangedUser = testLdapUser(
            cn = "unchanged!user.com",
            email = "unchanged@user.com",
            lastName = "Surname Two",
            memberOfCNs = listOf(
                DeltaConfig.DATAMART_DELTA_USER,
                "datamart-delta-user-orgCode2",
                "datamart-delta-user-orgCode3",
                "datamart-delta-access-group-1",
                "datamart-delta-access-group-2",
                "datamart-delta-access-group-2-orgCode2",
                "datamart-delta-access-group-2-orgCode3",
                "datamart-delta-delegate-access-group-2",
                "datamart-delta-data-providers",
                "datamart-delta-data-providers-orgCode2",
                "datamart-delta-data-providers-orgCode3",
                "datamart-delta-data-certifiers",
                "datamart-delta-data-certifiers-orgCode2",
                "datamart-delta-data-certifiers-orgCode3",
            ),
            mobile = "0123456789",
            positionInOrganisation = "test position",
        )
        private val modifications = slot<Array<ModificationItem>>()
        private const val NON_EXISTENT_USER_CN = "fake!user.com"
        private const val NON_EXISTENT_USER_EMAIL = "fake@user.com"

        private val organisations = listOf(
            OrganisationNameAndCode("orgCode2", "Org 2"), OrganisationNameAndCode("orgCode3", "Org 3")
        )
        @Suppress("BooleanLiteralArgument")
        private val accessGroups = listOf(
            AccessGroup("access-group-1", "STATS", "access group 1", false, false),
            AccessGroup("access-group-2", "STATS", "access group 2", false, false),
            AccessGroup("access-group-3", "STATS", "access group 3", false, false),
        )

        private fun getUserDetailsJson(email: String): JsonElement {
            return Json.parseToJsonElement(
                "{\"id\":\"$email\"," +
                    "\"enabled\":false," +
                    "\"email\":\"$email\"," +
                    "\"lastName\":\"Surname Two\"," +
                    "\"firstName\":\"Test\"," +
                    "\"telephone\":\"\"," +
                    "\"mobile\":\"0123456789\"," +
                    "\"position\":\"test position\"," +
                    "\"accessGroups\":[\"datamart-delta-access-group-1\",\"datamart-delta-access-group-2\"]," +
                    "\"accessGroupDelegates\":[\"datamart-delta-access-group-2\"]," +
                    "\"accessGroupOrganisations\":{\"datamart-delta-access-group-2\":[\"orgCode2\", \"orgCode3\"]}," +
                    "\"roles\":[\"datamart-delta-data-providers\",\"datamart-delta-data-certifiers\"]," +
                    "\"externalRoles\":[]," +
                    "\"organisations\":[\"orgCode2\", \"orgCode3\"]," +
                    "\"comment\":\"\"}"
            )
        }

        @BeforeClass
        @JvmStatic
        fun setup() {
            oauthSessionService = mockk<OAuthSessionService>()
            userLookupService = mockk<UserLookupService>()
            userGUIDMapService = mockk<UserGUIDMapService>()
            userService = mockk<UserService>()
            groupService = mockk<GroupService>()
            organisationService = mockk<OrganisationService>()
            accessGroupsService = mockk<AccessGroupsService>()
            accessGroupDCLGMembershipUpdateEmailService = mockk<AccessGroupDCLGMembershipUpdateEmailService>()

            val requestBodyMapper = DeltaUserPermissionsRequestMapper(
                organisationService, accessGroupsService
            )
            controller = AdminEditUserController(
                userLookupService,
                userGUIDMapService,
                userService,
                groupService,
                requestBodyMapper,
                accessGroupDCLGMembershipUpdateEmailService,
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
                            route("/edit-user") {
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
