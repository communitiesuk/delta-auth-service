package uk.gov.communities.delta.controllers

import io.ktor.client.*
import io.ktor.client.request.forms.*
import io.ktor.client.statement.*
import io.ktor.http.*
import io.ktor.server.routing.*
import io.ktor.server.testing.*
import io.ktor.test.dispatcher.*
import io.mockk.coEvery
import io.mockk.every
import io.mockk.mockk
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import org.junit.AfterClass
import org.junit.BeforeClass
import org.junit.Test
import uk.gov.communities.delta.auth.controllers.internal.OAuthTokenController
import uk.gov.communities.delta.auth.plugins.configureSerialization
import uk.gov.communities.delta.auth.saml.SAMLTokenService
import uk.gov.communities.delta.auth.services.*
import uk.gov.communities.delta.helper.testLdapUser
import uk.gov.communities.delta.helper.testServiceClient
import java.time.Instant
import kotlin.test.assertContains
import kotlin.test.assertEquals


class OAuthTokenControllerTest {

    @Test
    fun testTokenEndpoint() = testSuspend {
        testClient.submitForm(
            url = "/token",
            formParameters = parameters {
                append("code", "code")
                append("client_id", client.clientId)
                append("client_secret", client.clientSecret)
            }
        ).apply {
            assertEquals(HttpStatusCode.OK, status)
            val response = Json.parseToJsonElement(bodyAsText()).jsonObject
            assertEquals(session.authToken, response["access_token"].toString().trim('"'))
            assertEquals("SAML Token", response["saml_token"].toString().trim('"'))
            assertEquals("user", response["delta_ldap_user"]!!.jsonObject["cn"].toString().trim('"'))
            assertEquals("false", response["is_new_user"].toString().trim('"'))
        }
    }

    @Test
    fun testInvalidClientSecret() = testSuspend {
        testClient.submitForm(
            url = "/token",
            formParameters = parameters {
                append("code", "code")
                append("client_id", client.clientId)
                append("client_secret", "invalid")
            }
        ).apply {
            assertEquals(HttpStatusCode.BadRequest, status)
            assertContains(bodyAsText(), "invalid_client")
        }
    }

    @Test
    fun testInvalidCode() = testSuspend {
        testClient.submitForm(
            url = "/token",
            formParameters = parameters {
                append("code", "invalid")
                append("client_id", client.clientId)
                append("client_secret", client.clientSecret)
            }
        ).apply {
            assertEquals(HttpStatusCode.BadRequest, status)
            assertContains(bodyAsText(), "invalid_grant")
        }
    }

    companion object {
        private lateinit var testApp: TestApplication
        private lateinit var testClient: HttpClient
        private lateinit var controller: OAuthTokenController
        private val client = testServiceClient()

        private val user = testLdapUser(cn = "user")
        private val authCode = AuthCode("code", user.getGUID(), client, Instant.now(), "trace", false)
        private val session =
            OAuthSession(1, user.cn, user.getGUID(), client, "accessToken", Instant.now(), "trace", false)

        private val authorizationCodeService = mockk<AuthorizationCodeService>()
        private val userLookupService = mockk<UserLookupService>()
        private val samlTokenService = mockk<SAMLTokenService>()
        private val oauthSessionService = mockk<OAuthSessionService>()
        private val accessGroupsService = mockk<AccessGroupsService>()
        private val organisationService = mockk<OrganisationService>()
        private val userAuditService = mockk<UserAuditService>()
        private val memberOfToDeltaRolesMapper = mockk<MemberOfToDeltaRolesMapper>()

        @Suppress("MoveLambdaOutsideParentheses")
        @BeforeClass
        @JvmStatic
        fun setup() {
            coEvery { authorizationCodeService.lookupAndInvalidate(any(), client) } answers { null }
            coEvery { authorizationCodeService.lookupAndInvalidate(authCode.code, client) } answers { authCode }
            coEvery { oauthSessionService.create(authCode, client) } answers { session }
            coEvery { userLookupService.lookupCurrentUser(session) }.returns(user)
            coEvery { accessGroupsService.getAllAccessGroups() }.returns(listOf())
            coEvery { organisationService.findAllNamesAndCodes() }.returns(listOf())
            coEvery { userAuditService.checkIsNewUser(user.getGUID()) }.returns(false)
            every { memberOfToDeltaRolesMapper.map(any()) }.returns(
                MemberOfToDeltaRolesMapper.Roles(
                    emptyList(),
                    emptyList(),
                    emptyList(),
                    emptyList()
                )
            )
            every {
                samlTokenService.generate(
                    client.samlCredential,
                    user,
                    session.createdAt,
                    any()
                )
            } answers { "SAML Token" }
            controller = OAuthTokenController(
                listOf(client), authorizationCodeService, userLookupService, samlTokenService, oauthSessionService,
                accessGroupsService, organisationService, { _, _, _ -> memberOfToDeltaRolesMapper }, userAuditService
            )

            testApp = TestApplication {
                application {
                    configureSerialization()
                    routing {
                        route("/token") {
                            controller.route(this)
                        }
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
