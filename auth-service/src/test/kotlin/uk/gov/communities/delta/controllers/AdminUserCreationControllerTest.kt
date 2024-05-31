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
import jakarta.mail.Authenticator
import jakarta.mail.PasswordAuthentication
import junit.framework.TestCase.assertTrue
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement
import org.apache.commons.lang3.builder.EqualsBuilder
import org.junit.*
import uk.gov.communities.delta.auth.config.*
import uk.gov.communities.delta.auth.controllers.internal.AdminUserCreationController
import uk.gov.communities.delta.auth.controllers.internal.DeltaUserDetailsRequest
import uk.gov.communities.delta.auth.controllers.internal.DeltaUserPermissionsRequestMapper
import uk.gov.communities.delta.auth.plugins.ApiError
import uk.gov.communities.delta.auth.plugins.configureSerialization
import uk.gov.communities.delta.auth.repositories.LdapRepository
import uk.gov.communities.delta.auth.repositories.LdapUser
import uk.gov.communities.delta.auth.security.CLIENT_HEADER_AUTH_NAME
import uk.gov.communities.delta.auth.security.OAUTH_ACCESS_BEARER_TOKEN_AUTH_NAME
import uk.gov.communities.delta.auth.security.clientHeaderAuth
import uk.gov.communities.delta.auth.services.*
import uk.gov.communities.delta.auth.withBearerTokenAuth
import uk.gov.communities.delta.helper.testLdapUser
import uk.gov.communities.delta.helper.testServiceClient
import java.time.Instant
import java.util.*
import kotlin.test.assertEquals

class AdminUserCreationControllerTest {

    @Test
    fun testAdminCreateUser() = testSuspend {
        coEvery {
            userService.createUser(capture(user), any(), any(), any())
        } returns getLdapUserWithDetails(NEW_STANDARD_USER_EMAIL)
        testClient.post("/create-user") {
            contentType(ContentType.Application.Json)
            setBody(getUserDetailsJson(NEW_STANDARD_USER_EMAIL))
            headers {
                append("Authorization", "Bearer ${adminSession.authToken}")
                append("Delta-Client", "${client.clientId}:${client.clientSecret}")
            }
        }.apply {
            assertEquals(HttpStatusCode.OK, status)
            coVerify(exactly = 1) { userService.createUser(any(), null, adminSession, any()) }
            val expectedUser = UserService.ADUser(
                ldapConfig,
                getDeltaUserDetails(NEW_STANDARD_USER_EMAIL),
                null
            )
            assertCapturedUserIsAsExpected(expectedUser)
            verifyCorrectGroupsAdded()
            val expectedLdapUser = getLdapUserWithDetails(NEW_STANDARD_USER_EMAIL)
            coVerify(exactly = 1) {
                emailService.sendSetPasswordEmail(
                    expectedLdapUser.firstName,
                    any(),
                    expectedLdapUser.cn,
                    expectedLdapUser.getGUID(),
                    adminSession,
                    userLookupService,
                    any(),
                    any()
                )
            }
            verify {
                accessGroupDCLGMembershipUpdateEmailService.sendNotificationEmailsForChangeToUserAccessGroups(
                    AccessGroupDCLGMembershipUpdateEmailService.UpdatedUser(
                        NEW_STANDARD_USER_EMAIL,
                        "testFirst testLast"
                    ),
                    adminUser,
                    emptyList(),
                    setOf(
                        AccessGroupRole("access-group-1", "access group 1", "STATS", emptyList(), false),
                        AccessGroupRole(
                            "access-group-2", "access group 2", "STATS",
                            listOf("orgCode1", "orgCode2"), true
                        ),
                    ),
                )
            }
            confirmVerified(emailService, groupService, userService, accessGroupDCLGMembershipUpdateEmailService)
            assertEquals("{\"message\":\"User created successfully\"}", bodyAsText())
        }
    }

    @Test
    fun testUserMakingRequestNotExisting() = testSuspend {
        coEvery {
            userLookupService.lookupCurrentUser(adminSession)
        } throws LdapRepository.NoUserException("Test exception")
        Assert.assertThrows(LdapRepository.NoUserException::class.java) {
            runBlocking {
                testClient.post("/create-user") {
                    contentType(ContentType.Application.Json)
                    setBody(getUserDetailsJson(NEW_STANDARD_USER_EMAIL))
                    headers {
                        append("Authorization", "Bearer ${adminSession.authToken}")
                        append("Delta-Client", "${client.clientId}:${client.clientSecret}")
                    }
                }
            }
        }
    }

    @Test
    fun testNonAdminMakingRequest() = testSuspend {
        Assert.assertThrows(ApiError::class.java) {
            runBlocking {
                testClient.post("/create-user") {
                    headers {
                        append("Authorization", "Bearer ${userSession.authToken}")
                        append("Delta-Client", "${client.clientId}:${client.clientSecret}")
                    }
                    contentType(ContentType.Application.Json)
                    setBody(getUserDetailsJson(NEW_STANDARD_USER_EMAIL))
                }
            }
        }.apply {
            assertEquals("forbidden", errorCode)
        }
    }

    @Test
    fun testAdminCreateSSOUser() = testSuspend {
        coEvery {
            userService.createUser(capture(user), any(), any(), any())
        } returns getLdapUserWithDetails(NEW_SSO_USER_EMAIL)
        testClient.post("/create-user") {
            contentType(ContentType.Application.Json)
            setBody(getUserDetailsJson(NEW_SSO_USER_EMAIL))
            headers {
                append("Authorization", "Bearer ${adminSession.authToken}")
                append("Delta-Client", "${client.clientId}:${client.clientSecret}")
            }
        }.apply {
            assertEquals(HttpStatusCode.OK, status)
            coVerify(exactly = 1) { userService.createUser(any(), requiredSSOClient, adminSession, any()) }
            val expectedUser = UserService.ADUser(
                ldapConfig,
                getDeltaUserDetails(NEW_SSO_USER_EMAIL),
                requiredSSOClient
            )
            assertCapturedUserIsAsExpected(expectedUser, false)
            verifyCorrectGroupsAdded()
            coVerify(exactly = 0) {
                emailService.sendSetPasswordEmail(any(), any(), any(), any(), any(), any(), any(), any())
            }
            assertEquals(
                "{\"message\":\"User created. Single Sign On (SSO) is enabled for this user based on their email domain. The account has been activated automatically, no email has been sent.\"}",
                bodyAsText()
            )
        }
    }

    @Test
    fun testAdminCreateNotRequiredSSOUser() = testSuspend {
        coEvery {
            userService.createUser(capture(user), any(), any(), any())
        } returns getLdapUserWithDetails(NEW_NOT_REQUIRED_SSO_USER)
        testClient.post("/create-user") {
            contentType(ContentType.Application.Json)
            setBody(getUserDetailsJson(NEW_NOT_REQUIRED_SSO_USER))
            headers {
                append("Authorization", "Bearer ${adminSession.authToken}")
                append("Delta-Client", "${client.clientId}:${client.clientSecret}")
            }
        }.apply {
            assertEquals(HttpStatusCode.OK, status)
            coVerify(exactly = 1) { userService.createUser(any(), notRequiredSSOClient, adminSession, any()) }
            val expectedUser = UserService.ADUser(
                ldapConfig,
                getDeltaUserDetails(NEW_NOT_REQUIRED_SSO_USER),
                notRequiredSSOClient
            )
            assertCapturedUserIsAsExpected(expectedUser)
            verifyCorrectGroupsAdded()
            val expectedLdapUser = getLdapUserWithDetails(NEW_NOT_REQUIRED_SSO_USER)
            coVerify(exactly = 1) {
                emailService.sendSetPasswordEmail(
                    expectedLdapUser.firstName,
                    any(),
                    expectedLdapUser.cn,
                    expectedLdapUser.getGUID(),
                    adminSession,
                    userLookupService,
                    any(),
                    any()
                )
            }
            assertEquals("{\"message\":\"User created successfully\"}", bodyAsText())
        }
    }

    @Test
    fun testAdminCreateAlreadyExistingUser() = testSuspend {
        Assert.assertThrows(ApiError::class.java) {
            runBlocking {
                testClient.post("/create-user") {
                    contentType(ContentType.Application.Json)
                    setBody(getUserDetailsJson(OLD_STANDARD_USER_EMAIL))
                    headers {
                        append("Authorization", "Bearer ${adminSession.authToken}")
                        append("Delta-Client", "${client.clientId}:${client.clientSecret}")
                    }
                }
            }
        }.apply {
            assertEquals("user_already_exists", errorCode)
            coVerify(exactly = 0) { userService.createUser(any(), any(), any(), any()) }
        }
    }

    @Test
    fun testAdminCreateInvalidEmail() = testSuspend {
        Assert.assertThrows(ApiError::class.java) {
            runBlocking {
                testClient.post("/create-user") {
                    contentType(ContentType.Application.Json)
                    setBody(getUserDetailsJson(NEW_INVALID_USER_EMAIL))
                    headers {
                        append("Authorization", "Bearer ${adminSession.authToken}")
                        append("Delta-Client", "${client.clientId}:${client.clientSecret}")
                    }
                }
            }
        }.apply {
            assertEquals("invalid_email", errorCode)
            coVerify(exactly = 0) { userService.createUser(any(), any(), any(), any()) }
        }
    }

    @Test
    fun testErrorHandlingDuringCreation() = testSuspend {
        coEvery { userService.createUser(any(), any(), any(), any()) } throws Exception()
        Assert.assertThrows(ApiError::class.java) {
            runBlocking {
                testClient.post("/create-user") {
                    contentType(ContentType.Application.Json)
                    setBody(getUserDetailsJson(NEW_STANDARD_USER_EMAIL))
                    headers {
                        append("Authorization", "Bearer ${adminSession.authToken}")
                        append("Delta-Client", "${client.clientId}:${client.clientSecret}")
                    }
                }
            }
        }.apply {
            assertEquals("error_creating_user", errorCode)
        }
    }

    @Test
    fun testErrorHandlingDuringAddingToGroup() = testSuspend {
        coEvery {
            userService.createUser(capture(user), any(), any(), any())
        } returns getLdapUserWithDetails(NEW_STANDARD_USER_EMAIL)
        coEvery { groupService.addUserToGroup(any(), any(), any(), any(), any()) } throws Exception()
        Assert.assertThrows(ApiError::class.java) {
            runBlocking {
                testClient.post("/create-user") {
                    contentType(ContentType.Application.Json)
                    setBody(getUserDetailsJson(NEW_STANDARD_USER_EMAIL))
                    headers {
                        append("Authorization", "Bearer ${adminSession.authToken}")
                        append("Delta-Client", "${client.clientId}:${client.clientSecret}")
                    }
                }
            }
        }.apply {
            assertEquals("error_adding_user_to_groups", errorCode)
        }
    }

    @Test
    fun testErrorHandlingDuringEmailSending() = testSuspend {
        coEvery {
            userService.createUser(capture(user), any(), any(), any())
        } returns getLdapUserWithDetails(NEW_STANDARD_USER_EMAIL)
        coEvery {
            emailService.sendSetPasswordEmail(any(), any(), any(), any(), any(), any(), any(), any())
        } throws Exception()
        Assert.assertThrows(ApiError::class.java) {
            runBlocking {
                testClient.post("/create-user") {
                    contentType(ContentType.Application.Json)
                    setBody(getUserDetailsJson(NEW_STANDARD_USER_EMAIL))
                    headers {
                        append("Authorization", "Bearer ${adminSession.authToken}")
                        append("Delta-Client", "${client.clientId}:${client.clientSecret}")
                    }
                }
            }
        }.apply {
            assertEquals("error_sending_email", errorCode)
        }
    }

    @Before
    fun resetMocks() {
        user.clear()
        clearAllMocks()
        coEvery {
            oauthSessionService.retrieveFomAuthToken(
                adminSession.authToken,
                client
            )
        } answers { adminSession }
        coEvery {
            oauthSessionService.retrieveFomAuthToken(
                userSession.authToken,
                client
            )
        } answers { userSession }
        coEvery { userLookupService.lookupCurrentUser(adminSession) } returns adminUser
        coEvery { userLookupService.lookupCurrentUser(userSession) } returns regularUser
        coEvery { userLookupService.userIfExists(NEW_STANDARD_USER_EMAIL) } returns null
        coEvery { userLookupService.userIfExists(NEW_INVALID_USER_EMAIL) } returns null
        coEvery { userLookupService.userIfExists(NEW_SSO_USER_EMAIL) } returns null
        coEvery { userLookupService.userIfExists(NEW_NOT_REQUIRED_SSO_USER) } returns null
        coEvery {
            userLookupService.userIfExists(OLD_STANDARD_USER_EMAIL)
        } returns getLdapUserWithDetails(OLD_STANDARD_USER_EMAIL)
        coEvery { groupService.addUserToGroup(any(), any(), any(), any(), any()) } just runs
        coEvery { emailService.sendSetPasswordEmail(any(), any(), any(), any(), any(), any(), any(), any()) } just runs
        coEvery { setPasswordTokenService.createToken(any(), any()) } returns "passwordToken"
        coEvery { organisationService.findAllNamesAndCodes() } returns listOf(
            OrganisationNameAndCode("orgCode1", "Org 1"), OrganisationNameAndCode("orgCode2", "Org 2")
        )
        @Suppress("BooleanLiteralArgument")
        coEvery { accessGroupsService.getAllAccessGroups() } returns listOf(
            AccessGroup("access-group-1", "STATS", "access group 1", false, false),
            AccessGroup("access-group-2", "STATS", "access group 2", false, false),
        )
        every {
            accessGroupDCLGMembershipUpdateEmailService
                .sendNotificationEmailsForChangeToUserAccessGroups(any(), any(), any(), any())
        } just runs
    }

    companion object {
        private lateinit var testApp: TestApplication
        private lateinit var testClient: HttpClient
        private lateinit var controller: AdminUserCreationController

        private val oauthSessionService = mockk<OAuthSessionService>()

        private val ldapConfig = LDAPConfig("testInvalidUrl", "", "", "", "", "", "", "", "")
        private val requiredSSOClient = AzureADSSOClient("dev", "", "", "", "@required.sso.domain.uk", required = true)
        private val notRequiredSSOClient =
            AzureADSSOClient("dev", "", "", "", "@not.required.sso.domain.uk", required = false)

        private val ssoConfig =
            AzureADSSOConfig(listOf(requiredSSOClient, notRequiredSSOClient))
        private val authenticator: Authenticator = object : Authenticator() {
            override fun getPasswordAuthentication(): PasswordAuthentication {
                return PasswordAuthentication("", "")
            }
        }
        private val emailConfig = EmailConfig(Properties(), authenticator, "", "", "", "", false, emptyList())
        private val userLookupService = mockk<UserLookupService>()
        private val userService = mockk<UserService>()
        private val groupService = mockk<GroupService>()
        private val emailService = mockk<EmailService>()
        private val setPasswordTokenService = mockk<SetPasswordTokenService>()
        private val organisationService = mockk<OrganisationService>()
        private val accessGroupsService = mockk<AccessGroupsService>()
        private val accessGroupDCLGMembershipUpdateEmailService = mockk<AccessGroupDCLGMembershipUpdateEmailService>()

        private val user = slot<UserService.ADUser>()

        private val client = testServiceClient()
        private val adminUser = testLdapUser(cn = "admin", memberOfCNs = listOf(DeltaConfig.DATAMART_DELTA_ADMIN))
        private val regularUser = testLdapUser(cn = "user", memberOfCNs = emptyList())

        private val adminSession =
            OAuthSession(
            1, adminUser.cn, adminUser.getGUID(), client, "adminAccessToken", Instant.now(), "trace", false
        )
        private val userSession =
            OAuthSession(
            1, regularUser.cn, regularUser.getGUID(), client, "userAccessToken", Instant.now(), "trace", false
        )

        private fun getUserDetailsJson(email: String): JsonElement {
            return Json.parseToJsonElement(
                "{\"id\":\"\"," +
                    "\"enabled\":false," +
                    "\"email\":\"$email\"," +
                    "\"lastName\":\"testLast\"," +
                    "\"firstName\":\"testFirst\"," +
                    "\"telephone\":\"0123456789\"," +
                    "\"mobile\":\"0987654321\"," +
                    "\"position\":\"test position\"," +
                    "\"accessGroups\":[\"datamart-delta-access-group-2\",\"datamart-delta-access-group-1\"]," +
                    "\"accessGroupDelegates\":[\"datamart-delta-access-group-2\"]," +
                    "\"accessGroupOrganisations\":{\"datamart-delta-access-group-2\":[\"orgCode1\", \"orgCode2\"]}," +
                    "\"roles\":[\"datamart-delta-data-providers\",\"datamart-delta-data-certifiers\"]," +
                    "\"externalRoles\":[]," +
                    "\"organisations\":[\"orgCode1\", \"orgCode2\"]," +
                    "\"comment\":\"test comment\"}"
            )
        }

        private fun getDeltaUserDetails(email: String): DeltaUserDetailsRequest {
            return DeltaUserDetailsRequest(
                "",
                false,
                email,
                "testLast",
                "testFirst",
                "0123456789",
                "0987654321",
                "test position",
                null,
                listOf("datamart-delta-access-group-2", "datamart-delta-access-group-1"),
                listOf("datamart-delta-access-group-2"),
                mapOf("datamart-delta-access-group-2" to listOf("orgCode1", "orgCode2")),
                listOf("datamart-delta-data-providers", "datamart-delta-data-certifiers"),
                emptyList(),
                listOf("orgCode1", "orgCode2"),
                "test comment",
                null
            )
        }

        private fun getLdapUserWithDetails(email: String): LdapUser {
            val cn = LDAPConfig.emailToCN(email)
            return testLdapUser(
                dn = ldapConfig.deltaUserDnFormat.format(cn),
                cn = cn,
                memberOfCNs = groups,
                email = email,
                firstName = "testFirst",
                lastName = "testLast",
                fullName = "testFirst testLast",
                accountEnabled = false,
                javaUUIDObjectGuid = "00112233-4455-6677-8899-aabbccddeeff",
                telephone = "0123456789",
                mobile = "0987654321",
                comment = "test comment",
                notificationStatus = "active",
            )
        }

        private val groups = listOf(
            "datamart-delta-user",
            "datamart-delta-user-orgCode1",
            "datamart-delta-user-orgCode2",
            "datamart-delta-access-group-2",
            "datamart-delta-access-group-2-orgCode1",
            "datamart-delta-access-group-2-orgCode2",
            "datamart-delta-access-group-1",
            "datamart-delta-delegate-access-group-2",
            "datamart-delta-data-certifiers",
            "datamart-delta-data-certifiers-orgCode1",
            "datamart-delta-data-certifiers-orgCode2",
            "datamart-delta-data-providers",
            "datamart-delta-data-providers-orgCode1",
            "datamart-delta-data-providers-orgCode2",
        )

        private fun verifyCorrectGroupsAdded() {
            groups.forEach {
                coVerify(exactly = 1) { groupService.addUserToGroup(any(), it, any(), adminSession, userLookupService) }
            }
            coVerify(exactly = groups.size) { groupService.addUserToGroup(any(), any(), any(), any(), any()) }
        }

        private fun assertCapturedUserIsAsExpected(
            expectedUser: UserService.ADUser,
            includePasswordInCheck: Boolean = true
        ) {
            if (includePasswordInCheck) assertTrue(EqualsBuilder.reflectionEquals(expectedUser, user.captured))
            else assertTrue(EqualsBuilder.reflectionEquals(expectedUser, user.captured, "password"))
            // If the above line is failing the below lines can be used to give a more comprehensible failure
            // assertEquals(expectedUser.ldapConfig, user.captured.ldapConfig)
            // assertEquals(expectedUser.cn, user.captured.cn)
            // assertEquals(expectedUser.givenName, user.captured.givenName)
            // assertEquals(expectedUser.sn, user.captured.sn)
            // assertEquals(expectedUser.mail, user.captured.mail)
            // assertEquals(expectedUser.userAccountControl, user.captured.userAccountControl)
            // assertEquals(expectedUser.dn, user.captured.dn)
            // assertEquals(expectedUser.userPrincipalName, user.captured.userPrincipalName)
            // assertEquals(expectedUser.notificationStatus, user.captured.notificationStatus)
            // if (includePasswordInCheck) assertEquals(expectedUser.password, user.captured.password)
            // assertEquals(expectedUser.comment, user.captured.comment)
            // assertEquals(expectedUser.telephone, user.captured.telephone)
            // assertEquals(expectedUser.mobile, user.captured.mobile)
            // assertEquals(expectedUser.reasonForAccess, user.captured.reasonForAccess)
            // assertEquals(expectedUser.position, user.captured.position)
            // assertEquals(expectedUser.objClasses, user.captured.objClasses)
        }

        private const val NEW_STANDARD_USER_EMAIL = "new.user@test.com"
        private const val NEW_INVALID_USER_EMAIL = "new.user.@test.com"
        private const val NEW_SSO_USER_EMAIL = "new.user@required.sso.domain.uk"
        private const val NEW_NOT_REQUIRED_SSO_USER = "new.user@not.required.sso.domain.uk"
        private const val OLD_STANDARD_USER_EMAIL = "old.user@test.com"
        private const val OLD_SSO_USER_EMAIL = "old.user@required.sso.domain.uk"
        private const val OLD_NOT_REQUIRED_SSO_USER = "old.user@not.required.sso.domain.uk"

        @BeforeClass
        @JvmStatic
        fun setup() {
            controller = AdminUserCreationController(
                ldapConfig,
                ssoConfig,
                emailConfig,
                userLookupService,
                userService,
                groupService,
                emailService,
                setPasswordTokenService,
                DeltaUserPermissionsRequestMapper(organisationService, accessGroupsService),
                accessGroupDCLGMembershipUpdateEmailService,
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
                            route("/create-user") {
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
