package uk.gov.communities.delta.controllers

import io.ktor.client.*
import io.ktor.client.plugins.contentnegotiation.*
import io.ktor.client.request.*
import io.ktor.http.*
import io.ktor.serialization.kotlinx.json.*
import io.ktor.server.application.*
import io.ktor.server.auth.*
import io.ktor.server.routing.*
import io.ktor.server.testing.*
import io.ktor.test.dispatcher.*
import io.mockk.*
import kotlinx.coroutines.runBlocking
import org.junit.*
import uk.gov.communities.delta.auth.config.DeltaConfig
import uk.gov.communities.delta.auth.controllers.internal.EditAccessGroupsController
import uk.gov.communities.delta.auth.controllers.internal.EditAccessGroupsController.*
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
import javax.naming.directory.*
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class EditAccessGroupsControllerTest {
    @Test
    fun testUserCanUpdateAccessGroups() = testSuspend {
        testClient.post("/access-groups") {
            headers {
                append("Authorization", "Bearer ${externalUserSession.authToken}")
                append("Delta-Client", "${client.clientId}:${client.clientSecret}")
            }
            contentType(ContentType.Application.Json)
            setBody(
                "{" +
                    "\"accessGroupsRequest\": {" +
                    "\"datamart-delta-access-group-1\": [\"orgCode1\", \"orgCode2\"], " +
                    "\"datamart-delta-access-group-2\": [\"orgCode2\"]}" +
                    ", \"userSelectedOrgs\": [\"orgCode1\", \"orgCode2\", \"orgCode3\"]" +
                    "}"
            )
        }.apply {
            assertEquals(HttpStatusCode.OK, status)
            coVerify(exactly = 1) {
                groupService.addUserToGroup(
                    externalUser, "datamart-delta-access-group-1-orgCode2", any(), null,
                )
            }
            coVerify(exactly = 1) {
                groupService.addUserToGroup(
                    externalUser, "datamart-delta-access-group-2-orgCode2", any(), null
                )
            }
            coVerify(exactly = 1) {
                groupService.removeUserFromGroup(
                    externalUser, "datamart-delta-access-group-1-orgCode3", any(), null
                )
            }
            coVerify(exactly = 1) {
                groupService.removeUserFromGroup(
                    externalUser, "datamart-delta-access-group-2-orgCode1", any(), null
                )
            }
            confirmVerified(groupService, accessGroupDCLGMembershipUpdateEmailService)
        }
    }

    @Test
    fun testUpdateAddDCLGAccessGroup() = testSuspend {
        every {
            accessGroupDCLGMembershipUpdateEmailService.sendNotificationEmailsForUserAddedToDCLGInAccessGroup(
                any(),
                any(),
                any(),
                any()
            )
        } just runs
        testClient.post("/access-groups") {
            headers {
                append("Authorization", "Bearer ${internalUserSession.authToken}")
                append("Delta-Client", "${client.clientId}:${client.clientSecret}")
            }
            contentType(ContentType.Application.Json)
            setBody(
                "{" +
                    "\"accessGroupsRequest\": {\"datamart-delta-access-group-3\": [\"dclg\"]}" +
                    ", \"userSelectedOrgs\": [\"dclg\"]" +
                    "}"
            )
        }.apply {
            assertEquals(HttpStatusCode.OK, status)
            coVerify(exactly = 1) {
                groupService.addUserToGroup(
                    internalUser, "datamart-delta-access-group-3-dclg", any(), null
                )
            }
            verify(exactly = 1) {
                accessGroupDCLGMembershipUpdateEmailService.sendNotificationEmailsForUserAddedToDCLGInAccessGroup(
                    AccessGroupDCLGMembershipUpdateEmailService.UpdatedUser(internalUser),
                    internalUser,
                    "access-group-3",
                    "access group 3",
                )
            }
            confirmVerified(groupService, accessGroupDCLGMembershipUpdateEmailService)
        }
    }

    @Test
    fun testCannotUpdateOrganisationsNotInEmailDomain() {
        Assert.assertThrows(ApiError::class.java) {
            runBlocking {
                testClient.post("/access-groups") {
                    headers {
                        append("Authorization", "Bearer ${externalUserSession.authToken}")
                        append("Delta-Client", "${client.clientId}:${client.clientSecret}")
                    }
                    contentType(ContentType.Application.Json)
                    setBody(
                        "{" +
                            "\"accessGroupsRequest\": {\"datamart-delta-access-group-1\": [\"not-in-domain\"]}" +
                            ", \"userSelectedOrgs\": [\"not-in-domain\"]" +
                            "}"
                    )
                }
            }
        }.apply {
            assertEquals(errorCode, "user_non_domain_organisation")
            confirmVerified(groupService, accessGroupDCLGMembershipUpdateEmailService)
        }
    }

    @Test
    fun testAccessGroupsForUnselectedOrgsAreNotRemoved() = testSuspend {
        testClient.post("/access-groups") {
            headers {
                append("Authorization", "Bearer ${externalUserSession.authToken}")
                append("Delta-Client", "${client.clientId}:${client.clientSecret}")
            }
            contentType(ContentType.Application.Json)
            setBody(
                "{" +
                    "\"accessGroupsRequest\": {\"datamart-delta-access-group-1\": [\"orgCode1\", \"orgCode2\"], \"datamart-delta-access-group-2\": []}" +
                    ", \"userSelectedOrgs\": [\"orgCode1\", \"orgCode2\"]" +
                    "}"
            )
        }.apply {
            assertEquals(HttpStatusCode.OK, status)
            coVerify(exactly = 1) {
                groupService.addUserToGroup(
                    externalUser, "datamart-delta-access-group-1-orgCode2", any(), null
                )
            }
            coVerify(exactly = 1) {
                groupService.removeUserFromGroup(
                    externalUser, "datamart-delta-access-group-2", any(), null
                )
            }
            coVerify(exactly = 1) {
                groupService.removeUserFromGroup(
                    externalUser, "datamart-delta-access-group-2-orgCode1", any(), null
                )
            }
            confirmVerified(groupService, accessGroupDCLGMembershipUpdateEmailService)
        }
    }

    @Test
    fun accessGroupIsAddedIfUserIsNotAlreadyMember() {
        val accessGroupsRequestMap = mapOf("ag1" to listOf("org1"))
        val currentAccessGroupsMap = mapOf<String, List<String>>()
        val selectedOrgs = setOf("org1")
        val actions =
            controller.generateAccessGroupActions(accessGroupsRequestMap, currentAccessGroupsMap, selectedOrgs)
        assertEquals(
            setOf(
                AddAccessGroupAction("ag1"),
                AddAccessGroupOrganisationAction("ag1", "org1"),
            ),
            actions
        )
    }

    @Test
    fun accessGroupIsRemovedIfUserIsMemberOfNoOrgsForIt() {
        val accessGroupsRequestMap = mapOf("ag1" to listOf<String>())
        val currentAccessGroupsMap = mapOf("ag1" to listOf("org1"))
        val selectedOrgs = setOf("org1")
        val actions =
            controller.generateAccessGroupActions(accessGroupsRequestMap, currentAccessGroupsMap, selectedOrgs)
        assertEquals(
            setOf(
                RemoveAccessGroupAction("ag1"),
                RemoveAccessGroupOrganisationAction("ag1", "org1"),
            ),
            actions
        )
    }

    @Test
    fun accessGroupIsNotRemovedIfUserIsMemberInUnselectedOrg() {
        val accessGroupsRequestMap = mapOf("ag1" to listOf<String>())
        val currentAccessGroupsMap = mapOf("ag1" to listOf("org2"))
        val selectedOrgs = setOf("org1")
        val actions =
            controller.generateAccessGroupActions(accessGroupsRequestMap, currentAccessGroupsMap, selectedOrgs)
        assertTrue { actions.isEmpty() }
    }

    @Test
    fun internalUserCannotUpdateGroupsWithEnableInternalUserFalse() = testSuspend {
        Assert.assertThrows(ApiError::class.java) {
            runBlocking {
                testClient.post("/access-groups") {
                    headers {
                        append("Authorization", "Bearer ${internalUserSession.authToken}")
                        append("Delta-Client", "${client.clientId}:${client.clientSecret}")
                    }
                    contentType(ContentType.Application.Json)
                    setBody("{\"accessGroupsRequest\": {\"datamart-delta-access-group-2\": [\"orgCode1\"]}, \"userSelectedOrgs\": [\"orgCode1\"]}")
                }
            }
        }.apply {
            assertEquals("internal_user_non_internal_group", errorCode)
            assertEquals(HttpStatusCode.Forbidden, statusCode)
            confirmVerified(groupService, accessGroupDCLGMembershipUpdateEmailService)
        }
    }

    @Test
    fun userCannotUpdateGroupsWithEnableOnlineRegistrationFalse() = testSuspend {
        Assert.assertThrows(ApiError::class.java) {
            runBlocking {
                testClient.post("/access-groups") {
                    headers {
                        append("Authorization", "Bearer ${externalUserSession.authToken}")
                        append("Delta-Client", "${client.clientId}:${client.clientSecret}")
                    }
                    contentType(ContentType.Application.Json)
                    setBody("{\"accessGroupsRequest\": {\"datamart-delta-access-group-3\": [\"orgCode1\"]}, \"userSelectedOrgs\": [\"orgCode1\"]}")
                }
            }
        }.apply {
            assertEquals("external_user_non_online_registration_group", errorCode)
            assertEquals(HttpStatusCode.Forbidden, statusCode)
            confirmVerified(groupService, accessGroupDCLGMembershipUpdateEmailService)
        }
    }

    @Test
    fun userCannotRequestGroupsThatDoNotExist() = testSuspend {
        Assert.assertThrows(ApiError::class.java) {
            runBlocking {
                testClient.post("/access-groups") {
                    headers {
                        append("Authorization", "Bearer ${externalUserSession.authToken}")
                        append("Delta-Client", "${client.clientId}:${client.clientSecret}")
                    }
                    contentType(ContentType.Application.Json)
                    setBody("{\"accessGroupsRequest\": {\"datamart-delta-fake_group\": []}, \"userSelectedOrgs\": [\"orgCode1\"]}")
                }
            }
        }.apply {
            assertEquals("nonexistent_group", errorCode)
            assertEquals(HttpStatusCode.BadRequest, statusCode)
            confirmVerified(groupService, accessGroupDCLGMembershipUpdateEmailService)
        }
    }

    @Test
    fun userCannotAddToOrganisationsNotAMemberOf() = testSuspend {
        Assert.assertThrows(ApiError::class.java) {
            runBlocking {
                testClient.post("/access-groups") {
                    headers {
                        append("Authorization", "Bearer ${externalUserSession.authToken}")
                        append("Delta-Client", "${client.clientId}:${client.clientSecret}")
                    }
                    contentType(ContentType.Application.Json)
                    setBody("{\"accessGroupsRequest\": {\"datamart-delta-access-group-1\": [\"orgCode4\"]}, \"userSelectedOrgs\": [\"orgCode4\"]}")
                }
            }
        }.apply {
            assertEquals("user_not_member_of_selected_organisation", errorCode)
            assertEquals(HttpStatusCode.BadRequest, statusCode)
            confirmVerified(groupService)
        }
    }

    @Test
    fun userCanAddOtherToAccessGroup() = testSuspend {
        coEvery { accessGroupsService.getAccessGroup("access-group-3") } returns mockk<AccessGroup>()
        testClient.post("/access-groups/add") {
            headers {
                append("Authorization", "Bearer ${internalUserSession.authToken}")
                append("Delta-Client", "${client.clientId}:${client.clientSecret}")
            }
            contentType(ContentType.Application.Json)
            setBody(
                "{" +
                    "\"userToEditCn\": \"${externalUser.cn}\"" +
                    ", \"accessGroupName\": \"access-group-3\"" +
                    ", \"organisationCodes\": [\"orgCode1\", \"orgCode2\"]}"
            )
        }.apply {
            assertEquals(HttpStatusCode.OK, status)
            coVerify(exactly = 1) {
                groupService.addUserToGroup(
                    externalUser, "datamart-delta-access-group-3", any(), internalUserSession,
                )
            }
            coVerify(exactly = 1) {
                groupService.addUserToGroup(
                    externalUser,
                    "datamart-delta-access-group-3-orgCode1",
                    any(),
                    internalUserSession,
                )
            }
            coVerify(exactly = 1) {
                groupService.addUserToGroup(
                    externalUser,
                    "datamart-delta-access-group-3-orgCode2",
                    any(),
                    internalUserSession,
                )
            }
            confirmVerified(groupService, accessGroupDCLGMembershipUpdateEmailService)
        }
    }

    @Test
    fun userCanAddAccessGroupWithComment() = testSuspend {
        coEvery { accessGroupsService.getAccessGroup("access-group-3") } returns mockk<AccessGroup>()
        testClient.post("/access-groups/add") {
            headers {
                append("Authorization", "Bearer ${internalUserSession.authToken}")
                append("Delta-Client", "${client.clientId}:${client.clientSecret}")
            }
            contentType(ContentType.Application.Json)
            setBody(
                "{" +
                    "\"userToEditCn\": \"${externalUser.cn}\"" +
                    ", \"accessGroupName\": \"access-group-3\"" +
                    ", \"organisationCodes\": [\"orgCode1\", \"orgCode2\"]" +
                    ", \"comment\": \"Mockk comment 1\"}"
            )
        }.apply {
            assertEquals(HttpStatusCode.OK, status)
            coVerify(exactly = 1) {
                groupService.addUserToGroup(
                    externalUser, "datamart-delta-access-group-3", any(), internalUserSession,
                )
            }
            coVerify(exactly = 1) {
                groupService.addUserToGroup(
                    externalUser,
                    "datamart-delta-access-group-3-orgCode1",
                    any(),
                    internalUserSession,
                )
            }
            coVerify(exactly = 1) {
                groupService.addUserToGroup(
                    externalUser,
                    "datamart-delta-access-group-3-orgCode2",
                    any(),
                    internalUserSession,
                )
            }
            coVerify(exactly = 1) {
                userService.updateUser(externalUser, capture(modifications), internalUserSession, any())
            }
            assertEquals(1, modifications.captured.size)
            assertTrue(modifications.captured.any { it.modificationOp == DirContext.ADD_ATTRIBUTE && it.attribute.id == "comment" && it.attribute.get() == "Mockk comment 1" })

            // Confirm all verifications
            confirmVerified( groupService, accessGroupDCLGMembershipUpdateEmailService, userService )
        }
    }

    @Test
    fun userCanAddAccessGroupWithCommentToExistingComment() = testSuspend {
        coEvery { accessGroupsService.getAccessGroup("access-group-3") } returns mockk<AccessGroup>()
        testClient.post("/access-groups/add") {
            headers {
                append("Authorization", "Bearer ${internalUserSession.authToken}")
                append("Delta-Client", "${client.clientId}:${client.clientSecret}")
            }
            contentType(ContentType.Application.Json)
            setBody(
                "{" +
                    "\"userToEditCn\": \"${externalUserWithExistingComments.cn}\"" +
                    ", \"accessGroupName\": \"access-group-3\"" +
                    ", \"organisationCodes\": [\"orgCode1\", \"orgCode2\"]" +
                    ", \"comment\": \"Mockk comment 1\"}"
            )
        }.apply {
            assertEquals(HttpStatusCode.OK, status)
            coVerify(exactly = 1) {
                groupService.addUserToGroup(
                    externalUserWithExistingComments, "datamart-delta-access-group-3", any(), internalUserSession,
                )
            }
            coVerify(exactly = 1) {
                groupService.addUserToGroup(
                    externalUserWithExistingComments,
                    "datamart-delta-access-group-3-orgCode1",
                    any(),
                    internalUserSession,
                )
            }
            coVerify(exactly = 1) {
                groupService.addUserToGroup(
                    externalUserWithExistingComments,
                    "datamart-delta-access-group-3-orgCode2",
                    any(),
                    internalUserSession,
                )
            }
            coVerify(exactly = 1) {
                userService.updateUser(externalUserWithExistingComments, capture(modifications), internalUserSession, any())
            }
            assertEquals(1, modifications.captured.size)
            assertTrue(modifications.captured.any { it.modificationOp == DirContext.REPLACE_ATTRIBUTE && it.attribute.id == "comment" && it.attribute.get() == "Existing comment 1\nMockk comment 1" })

            // Confirm all verifications
            confirmVerified( groupService, accessGroupDCLGMembershipUpdateEmailService, userService )
        }
    }

    @Test
    fun testAddDCLGMembership() = testSuspend {
        @Suppress("BooleanLiteralArgument")
        coEvery { accessGroupsService.getAccessGroup("access-group-3") } returns AccessGroup(
            "datamart-delta-access-group-3", "STATS", "access group 3", false, false
        )
        every {
            accessGroupDCLGMembershipUpdateEmailService.sendNotificationEmailsForUserAddedToDCLGInAccessGroup(
                any(), any(), any(), any()
            )
        } just runs
        testClient.post("/access-groups/add") {
            headers {
                append("Authorization", "Bearer ${internalUserSession.authToken}")
                append("Delta-Client", "${client.clientId}:${client.clientSecret}")
            }
            contentType(ContentType.Application.Json)
            setBody(
                "{" +
                    "\"userToEditCn\": \"${internalUser.cn}\"" +
                    ", \"accessGroupName\": \"access-group-3\"" +
                    ", \"organisationCodes\": [\"dclg\"]}"
            )
        }.apply {
            assertEquals(HttpStatusCode.OK, status)
            coVerify(exactly = 1) {
                groupService.addUserToGroup(
                    internalUser, "datamart-delta-access-group-3-dclg", any(), internalUserSession,
                )
            }
            verify(exactly = 1) {
                accessGroupDCLGMembershipUpdateEmailService.sendNotificationEmailsForUserAddedToDCLGInAccessGroup(
                    AccessGroupDCLGMembershipUpdateEmailService.UpdatedUser(internalUser),
                    internalUser,
                    "access-group-3",
                    "access group 3",
                )
            }
            confirmVerified(groupService, accessGroupDCLGMembershipUpdateEmailService)
        }
    }

    @Test
    fun cannotAddUserToInvalidAccessGroup() {
        coEvery { accessGroupsService.getAccessGroup(any()) } returns null
        Assert.assertThrows(ApiError::class.java) {
            runBlocking {
                testClient.post("/access-groups/add") {
                    headers {
                        append("Authorization", "Bearer ${internalUserSession.authToken}")
                        append("Delta-Client", "${client.clientId}:${client.clientSecret}")
                    }
                    contentType(ContentType.Application.Json)
                    setBody(
                        "{" +
                            "\"userToEditCn\": \"${externalUser.cn}\"" +
                            ", \"accessGroupName\": \"invalid-group\"" +
                            ", \"organisationCodes\": [\"orgCode1\", \"orgCode2\"]}"
                    )
                }
            }
        }.apply {
            assertEquals("nonexistent_group", errorCode)
            confirmVerified(groupService, accessGroupDCLGMembershipUpdateEmailService)
        }
    }

    @Test
    fun nonInternalUserCannotMakeSingleGroupRequest() {
        Assert.assertThrows(ApiError::class.java) {
            controller.validateIsInternalUser(externalUser)
        }.apply {
            assertEquals("non_internal_user_altering_access_group_membership", errorCode)
            assertEquals(HttpStatusCode.Forbidden, statusCode)
        }
    }

    @Test
    fun userCanRemoveOtherFromAccessGroup() = testSuspend {
        coEvery { accessGroupsService.getAccessGroup("access-group-2") } returns mockk<AccessGroup>()
        testClient.post("/access-groups/remove") {
            headers {
                append("Authorization", "Bearer ${internalUserSession.authToken}")
                append("Delta-Client", "${client.clientId}:${client.clientSecret}")
            }
            contentType(ContentType.Application.Json)
            setBody(
                "{" +
                    "\"userToEditCn\": \"${externalUser.cn}\"" +
                    ", \"accessGroupName\": \"access-group-2\"}"
            )
        }.apply {
            assertEquals(HttpStatusCode.OK, status)
            coVerify(exactly = 1) {
                groupService.removeUserFromGroup(
                    externalUser, "datamart-delta-access-group-2", any(), internalUserSession,
                )
            }
            coVerify(exactly = 1) {
                groupService.removeUserFromGroup(
                    externalUser,
                    "datamart-delta-access-group-2-orgCode1",
                    any(),
                    internalUserSession,
                )
            }
            confirmVerified(groupService, accessGroupDCLGMembershipUpdateEmailService)
        }
    }


    @Before
    fun resetMocks() {
        clearAllMocks()
        coEvery {
            oauthSessionService.retrieveFromAuthToken(
                externalUserSession.authToken,
                client
            )
        } answers { externalUserSession }
        coEvery {
            oauthSessionService.retrieveFromAuthToken(
                internalUserSession.authToken,
                client
            )
        } answers { internalUserSession }
        coEvery { userGUIDMapService.getGUIDFromCN(externalUser.cn) } returns externalUser.getGUID()
        coEvery { userGUIDMapService.getGUIDFromCN(externalUserWithExistingComments.cn) } returns externalUserWithExistingComments.getGUID()
        coEvery { userGUIDMapService.getGUIDFromCN(internalUser.cn) } returns internalUser.getGUID()
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
        coEvery { organisationService.findAllByEmail(externalUser.email) } returns listOf(
            Organisation("orgCode1", "Organisation Name 1"),
            Organisation("orgCode2", "Organisation Name 2"),
            Organisation("orgCode3", "Organisation Name 3"),
            Organisation("orgCode4", "Organisation Name 4"),
        )
        coEvery { organisationService.findAllByEmail(externalUserWithExistingComments.email) } returns listOf(
            Organisation("orgCode1", "Organisation Name 1"),
            Organisation("orgCode2", "Organisation Name 2"),
            Organisation("orgCode3", "Organisation Name 3"),
            Organisation("orgCode4", "Organisation Name 4"),
        )
        coEvery { organisationService.findAllByEmail(internalUser.email) } returns listOf(
            Organisation("orgCode1", "Organisation Name 1"),
            Organisation("orgCode2", "Organisation Name 2"),
            Organisation("dclg", "The Department"),
        )
        mockUserLookupService(
            userLookupService,
            listOf(Pair(internalUser, internalUserSession), Pair(externalUser, externalUserSession)),
            runBlocking { organisationService.findAllNamesAndCodes() },
            runBlocking { accessGroupsService.getAllAccessGroups() },
        )
        mockUserLookupService(
            userLookupService,
            listOf(Pair(internalUser, internalUserSession), Pair(externalUserWithExistingComments, externalUserWithExistingCommentsSession)),
            runBlocking { organisationService.findAllNamesAndCodes() },
            runBlocking { accessGroupsService.getAllAccessGroups() },
        )
        coEvery { groupService.addUserToGroup(externalUser, any(), any(), any()) } just runs
        coEvery { groupService.addUserToGroup(externalUserWithExistingComments, any(), any(), any()) } just runs
        coEvery { groupService.removeUserFromGroup(externalUser, any(), any(), any()) } just runs
        coEvery { groupService.removeUserFromGroup(externalUserWithExistingComments, any(), any(), any()) } just runs
        coEvery { groupService.addUserToGroup(internalUser, any(), any(), any()) } just runs
        coEvery { groupService.removeUserFromGroup(internalUser, any(), any(), any()) } just runs
        coEvery { userService.updateUser(externalUser, any(), any(), any()) } just runs
        coEvery { userService.updateUser(externalUserWithExistingComments, any(), any(), any()) } just runs
    }

    companion object {
        private lateinit var testApp: TestApplication
        private lateinit var testClient: HttpClient
        private lateinit var controller: EditAccessGroupsController

        private val oauthSessionService = mockk<OAuthSessionService>()

        private val userLookupService = mockk<UserLookupService>()
        private val userGUIDMapService = mockk<UserGUIDMapService>()
        private val userService = mockk<UserService>()
        private val groupService = mockk<GroupService>()
        private val organisationService = mockk<OrganisationService>()
        private val accessGroupsService = mockk<AccessGroupsService>()
        private val memberOfToDeltaRolesMapper = ::MemberOfToDeltaRolesMapper
        private val accessGroupDCLGMembershipUpdateEmailService = mockk<AccessGroupDCLGMembershipUpdateEmailService>()

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

        private val externalUserWithExistingComments = testLdapUser(
            cn = "external!user2.com",
            email = "external@user2.com",
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
            comment = "Existing comment 1",
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

        private val externalUserWithExistingCommentsSession =
            OAuthSession(
                1,
                externalUserWithExistingComments.cn,
                externalUserWithExistingComments.getGUID(),
                client,
                "externalUserWithCommentsToken",
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

        private val modifications = slot<Array<ModificationItem>>()

        @BeforeClass
        @JvmStatic
        fun setup() {
            controller = EditAccessGroupsController(
                userLookupService,
                userGUIDMapService,
                userService,
                groupService,
                organisationService,
                accessGroupsService,
                memberOfToDeltaRolesMapper,
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
                            post("/access-groups") {
                                controller.updateCurrentUserAccessGroups(call)
                            }
                            post("/access-groups/add") {
                                controller.addUserToAccessGroup(call)
                            }
                            post("/access-groups/remove") {
                                controller.removeUserFromAccessGroup(call)
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
