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
import jakarta.mail.Authenticator
import jakarta.mail.PasswordAuthentication
import junit.framework.TestCase.assertTrue
import kotlinx.coroutines.runBlocking
import org.apache.commons.lang3.builder.EqualsBuilder
import org.junit.*
import uk.gov.communities.delta.auth.bearerTokenRoutes
import uk.gov.communities.delta.auth.config.*
import uk.gov.communities.delta.auth.controllers.internal.AdminUserCreationController
import uk.gov.communities.delta.auth.plugins.ApiError
import uk.gov.communities.delta.auth.plugins.configureSerialization
import uk.gov.communities.delta.auth.security.CLIENT_HEADER_AUTH_NAME
import uk.gov.communities.delta.auth.security.OAUTH_ACCESS_BEARER_TOKEN_AUTH_NAME
import uk.gov.communities.delta.auth.security.clientHeaderAuth
import uk.gov.communities.delta.auth.services.*
import uk.gov.communities.delta.helper.testLdapUser
import uk.gov.communities.delta.helper.testServiceClient
import java.time.Instant
import java.util.*
import javax.naming.NameNotFoundException
import kotlin.test.assertEquals

class AdminUserCreationControllerTest {

    @Test
    fun testAdminCreateUser() = testSuspend {
        testClient.post("/bearer/create-user") {
            headers {
                append("Authorization", "Bearer ${adminSession.authToken}")
                append("Delta-Client", "${client.clientId}:${client.clientSecret}")
                setBody(getUserDetailsJsonString(NEW_STANDARD_USER_EMAIL))
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
            coVerify(exactly = 1) {
                emailService.sendSetPasswordEmail(
                    expectedUser.givenName,
                    any(),
                    expectedUser.cn,
                    adminSession,
                    any(),
                    any()
                )
            }
            assertEquals("User created successfully", bodyAsText())
        }
    }

    @Test
    fun testUserMakingRequestNotExisting() = testSuspend {
        coEvery { userLookupService.lookupUserByCn(adminUser.cn) } throws NameNotFoundException()
        Assert.assertThrows(NameNotFoundException::class.java) {
            runBlocking {
                testClient.post("/bearer/create-user") {
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
                testClient.post("/bearer/create-user") {
                    headers {
                        append("Authorization", "Bearer ${userSession.authToken}")
                        append("Delta-Client", "${client.clientId}:${client.clientSecret}")
                    }
                    parameter("text", "testing testing")
                }
            }
        }.apply {
            assertEquals("forbidden", errorCode)
        }
    }

    @Test
    fun testAdminCreateSSOUser() = testSuspend {
        testClient.post("/bearer/create-user") {
            headers {
                append("Authorization", "Bearer ${adminSession.authToken}")
                append("Delta-Client", "${client.clientId}:${client.clientSecret}")
                setBody(getUserDetailsJsonString(NEW_SSO_USER_EMAIL))
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
            coVerify(exactly = 0) { emailService.sendSetPasswordEmail(any(), any(), any(), any(), any(), any()) }
            assertEquals(
                "SSO user created, no email has been sent to the user since emails aren't sent to SSO users",
                bodyAsText()
            )
        }
    }

    @Test
    fun testAdminCreateNotRequiredSSOUser() = testSuspend {
        testClient.post("/bearer/create-user") {
            headers {
                append("Authorization", "Bearer ${adminSession.authToken}")
                append("Delta-Client", "${client.clientId}:${client.clientSecret}")
                setBody(getUserDetailsJsonString(NEW_NOT_REQUIRED_SSO_USER))
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
            coVerify(exactly = 1) {
                emailService.sendSetPasswordEmail(
                    expectedUser.givenName,
                    any(),
                    expectedUser.cn,
                    adminSession,
                    any(),
                    any()
                )
            }
            assertEquals("User created successfully", bodyAsText())
        }
    }

    @Test
    fun testAdminCreateAlreadyExistingUser() = testSuspend {
        Assert.assertThrows(ApiError::class.java) {
            runBlocking {
                testClient.post("/bearer/create-user") {
                    headers {
                        append("Authorization", "Bearer ${adminSession.authToken}")
                        append("Delta-Client", "${client.clientId}:${client.clientSecret}")
                        setBody(getUserDetailsJsonString(OLD_STANDARD_USER_EMAIL))
                    }
                }
            }
        }.apply {
            assertEquals("user_already_exists", errorCode)
            coVerify(exactly = 0) { userService.createUser(any(), any(), any(), any()) }
        }
    }

    @Test
    fun testErrorHandlingDuringCreation() = testSuspend {
        coEvery { userService.createUser(any(), any(), any(), any()) } throws Exception()
        Assert.assertThrows(ApiError::class.java) {
            runBlocking {
                testClient.post("/bearer/create-user") {
                    headers {
                        append("Authorization", "Bearer ${adminSession.authToken}")
                        append("Delta-Client", "${client.clientId}:${client.clientSecret}")
                        setBody(getUserDetailsJsonString(NEW_STANDARD_USER_EMAIL))
                    }
                }
            }
        }.apply {
            assertEquals("error_creating_user", errorCode)
        }
    }

    @Test
    fun testErrorHandlingDuringAddingToGroup() = testSuspend {
        coEvery { groupService.addUserToGroup(any(), any(), any(), any()) } throws Exception()
        Assert.assertThrows(ApiError::class.java) {
            runBlocking {
                testClient.post("/bearer/create-user") {
                    headers {
                        append("Authorization", "Bearer ${adminSession.authToken}")
                        append("Delta-Client", "${client.clientId}:${client.clientSecret}")
                        setBody(getUserDetailsJsonString(NEW_STANDARD_USER_EMAIL))
                    }
                }
            }
        }.apply {
            assertEquals("error_adding_user_to_groups", errorCode)
        }
    }

    @Test
    fun testErrorHandlingDuringEmailSending() = testSuspend {
        coEvery { emailService.sendSetPasswordEmail(any(), any(), any(), any(), any(), any()) } throws Exception()
        Assert.assertThrows(ApiError::class.java) {
            runBlocking {
                testClient.post("/bearer/create-user") {
                    headers {
                        append("Authorization", "Bearer ${adminSession.authToken}")
                        append("Delta-Client", "${client.clientId}:${client.clientSecret}")
                        setBody(getUserDetailsJsonString(NEW_STANDARD_USER_EMAIL))
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
        coEvery { userLookupService.lookupUserByCn(adminUser.cn) } returns adminUser
        coEvery { userLookupService.lookupUserByCn(regularUser.cn) } returns regularUser
        coEvery { userLookupService.userExists(LDAPConfig.emailToCN(NEW_STANDARD_USER_EMAIL)) } returns false
        coEvery { userLookupService.userExists(LDAPConfig.emailToCN(NEW_SSO_USER_EMAIL)) } returns false
        coEvery { userLookupService.userExists(LDAPConfig.emailToCN(NEW_NOT_REQUIRED_SSO_USER)) } returns false
        coEvery { userLookupService.userExists(LDAPConfig.emailToCN(OLD_STANDARD_USER_EMAIL)) } returns true
        coEvery { userLookupService.userExists(LDAPConfig.emailToCN(OLD_SSO_USER_EMAIL)) } returns true
        coEvery { userLookupService.userExists(LDAPConfig.emailToCN(OLD_NOT_REQUIRED_SSO_USER)) } returns true
        coEvery { userService.createUser(capture(user), any(), any(), any()) } just runs
        coEvery { groupService.addUserToGroup(any(), any(), any(), any()) } just runs
        coEvery { emailService.sendSetPasswordEmail(any(), any(), any(), any(), any(), any()) } just runs
        coEvery { setPasswordTokenService.createToken(any()) } returns "passwordToken"
    }

    companion object {
        private lateinit var testApp: TestApplication
        private lateinit var testClient: HttpClient
        private lateinit var controller: AdminUserCreationController

        private val oauthSessionService = mockk<OAuthSessionService>()

        private val ldapConfig = LDAPConfig("testInvalidUrl", "", "", "", "", "", "", "", "")
        private val deltaConfig = DeltaConfig.fromEnv()
        private val requiredSSOClient = AzureADSSOClient("dev", "", "", "", "@required.sso.domain", required = true)
        private val notRequiredSSOClient =
            AzureADSSOClient("dev", "", "", "", "@not.required.sso.domain", required = false)

        private val ssoConfig =
            AzureADSSOConfig(listOf(requiredSSOClient, notRequiredSSOClient))
        private val authenticator: Authenticator = object : Authenticator() {
            override fun getPasswordAuthentication(): PasswordAuthentication {
                return PasswordAuthentication("", "")
            }
        }
        private val emailConfig = EmailConfig(Properties(), authenticator, "", "", "", "")
        private val userLookupService = mockk<UserLookupService>()
        private val userService = mockk<UserService>()
        private val groupService = mockk<GroupService>()
        private val emailService = mockk<EmailService>()
        private val setPasswordTokenService = mockk<SetPasswordTokenService>()

        private val user = slot<UserService.ADUser>()

        private val client = testServiceClient()
        private val adminUser = testLdapUser(cn = "admin", memberOfCNs = listOf("datamart-delta-admin"))
        private val regularUser = testLdapUser(cn = "user", memberOfCNs = emptyList())

        private val adminSession = OAuthSession(1, adminUser.cn, client, "adminAccessToken", Instant.now(), "trace")
        private val userSession = OAuthSession(1, regularUser.cn, client, "userAccessToken", Instant.now(), "trace")

        private fun getUserDetailsJsonString(email: String): String {
            return "{\"id\":\"\"," +
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
                    "\"roles\":[\"datamart-delta-role-1\",\"datamart-delta-role-2\"]," +
                    "\"externalRoles\":[]," +
                    "\"organisations\":[\"orgCode1\", \"orgCode2\"]," +
                    "\"comment\":\"test comment\"}"
        }

//        {"id":"","enabled":false,"email":"test65@test610.com","lastName":"test dt610","firstName":"phoebe","telephone":"4564563","mobile":"2452345","position":"","accessGroups":["datamart-delta-abcdef","datamart-delta-aga-test-grant"],"accessGroupDelegates":["datamart-delta-abcdef","datamart-delta-aga-test-grant"],"accessGroupOrganisations":{"datamart-delta-abcdef":["pw-org-36616"]},"roles":["datamart-delta-setup-managers"],"externalRoles":[],"organisations":["pw-org-36616"],"comment":""}

        private fun getDeltaUserDetails(email: String): UserService.DeltaUserDetails {
            return UserService.DeltaUserDetails(
                "",
                false,
                email,
                "testLast",
                "testFirst",
                "0123456789",
                "0987654321",
                "test position",
                null,
                arrayOf("datamart-delta-access-group-2", "datamart-delta-access-group-1"),
                arrayOf("datamart-delta-access-group-2"),
                mapOf("datamart-delta-access-group-2" to arrayOf("orgCode1", "orgCode2")),
                arrayOf("datamart-delta-role-1", "datamart-delta-role-2"),
                emptyArray(),
                arrayOf("orgCode1", "orgCode2"),
                "test comment",
                null
            )
        }

        private fun verifyCorrectGroupsAdded() {
            coVerify(exactly = 1) { groupService.addUserToGroup(any(), "datamart-delta-user", any(), adminSession) }
            coVerify(exactly = 1) {
                groupService.addUserToGroup(any(), "datamart-delta-user-orgCode1", any(), adminSession)
            }
            coVerify(exactly = 1) {
                groupService.addUserToGroup(any(), "datamart-delta-user-orgCode2", any(), adminSession)
            }
            coVerify(exactly = 1) {
                groupService.addUserToGroup(any(), "datamart-delta-access-group-2", any(), adminSession)
            }
            coVerify(exactly = 1) {
                groupService.addUserToGroup(any(), "datamart-delta-access-group-2-orgCode1", any(), adminSession)
            }
            coVerify(exactly = 1) {
                groupService.addUserToGroup(any(), "datamart-delta-access-group-2-orgCode2", any(), adminSession)
            }
            coVerify(exactly = 1) {
                groupService.addUserToGroup(any(), "datamart-delta-access-group-1", any(), adminSession)
            }
            coVerify(exactly = 1) {
                groupService.addUserToGroup(any(), "datamart-delta-delegate-access-group-2", any(), adminSession)
            }
            coVerify(exactly = 1) { groupService.addUserToGroup(any(), "datamart-delta-role-2", any(), adminSession) }
            coVerify(exactly = 1) {
                groupService.addUserToGroup(any(), "datamart-delta-role-2-orgCode1", any(), adminSession)
            }
            coVerify(exactly = 1) {
                groupService.addUserToGroup(any(), "datamart-delta-role-2-orgCode2", any(), adminSession)
            }
            coVerify(exactly = 1) { groupService.addUserToGroup(any(), "datamart-delta-role-1", any(), adminSession) }
            coVerify(exactly = 1) {
                groupService.addUserToGroup(any(), "datamart-delta-role-1-orgCode1", any(), adminSession)
            }
            coVerify(exactly = 1) {
                groupService.addUserToGroup(any(), "datamart-delta-role-1-orgCode2", any(), adminSession)
            }
            coVerify(exactly = 14) { groupService.addUserToGroup(any(), any(), any(), any()) }
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
        private const val NEW_SSO_USER_EMAIL = "new.user@required.sso.domain"
        private const val NEW_NOT_REQUIRED_SSO_USER = "new.user@not.required.sso.domain"
        private const val OLD_STANDARD_USER_EMAIL = "old.user@test.com"
        private const val OLD_SSO_USER_EMAIL = "old.user@required.sso.domain"
        private const val OLD_NOT_REQUIRED_SSO_USER = "old.user@not.required.sso.domain"

        @BeforeClass
        @JvmStatic
        fun setup() {
            controller = AdminUserCreationController(
                ldapConfig,
                deltaConfig,
                ssoConfig,
                emailConfig,
                userLookupService,
                userService,
                groupService,
                emailService,
                setPasswordTokenService
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
                            controller,
                        )
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