package uk.gov.communities.delta.dbintegration

import io.ktor.server.application.*
import io.ktor.server.plugins.callid.*
import io.mockk.every
import io.mockk.mockk
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.BeforeClass
import org.junit.Test
import uk.gov.communities.delta.auth.config.AzureADSSOClient
import uk.gov.communities.delta.auth.services.UserAuditTrailRepo
import uk.gov.communities.delta.helper.testServiceClient
import kotlin.test.assertEquals
import kotlin.test.assertNull

class UserAuditTrailRepoTest {
    @Test
    fun testUserLoginAudit() {
        testDbPool.useConnectionBlocking("test_login_audit") {
            assertEquals(0, repo.getAuditForUser(it, "some.user!example.com").size)

            repo.userFormLoginAudit(it, "some.user!example.com", call)

            val audit = repo.getAuditForUser(it, "some.user!example.com")
            assertEquals(1, audit.size)
            assertEquals("some.user!example.com", audit[0].userCn)
            assertEquals(call.callId, audit[0].requestId)
            assertNull(audit[0].editingUserCn)
            assertEquals(UserAuditTrailRepo.AuditAction.FORM_LOGIN, audit[0].action)

            it.rollback()
        }
    }

    @Test
    fun testSSOLoginAudit() {
        testDbPool.useConnectionBlocking("test_sso_login_audit") {
            repo.userSSOLoginAudit(
                it, "some.user!example.com",
                AzureADSSOClient("sso-id", "", "", "", "@example.com"),
                "az-123", call,
            )

            val audit = repo.getAuditForUser(it, "some.user!example.com")
            assertEquals(1, audit.size)
            assertEquals("some.user!example.com", audit[0].userCn)
            assertEquals(call.callId, audit[0].requestId)
            assertNull(audit[0].editingUserCn)
            assertEquals(UserAuditTrailRepo.AuditAction.SSO_LOGIN, audit[0].action)
            assertEquals("az-123", audit[0].actionData.jsonObject["azureUserObjectId"]!!.jsonPrimitive.content)

            it.rollback()
        }
    }

    companion object {
        lateinit var repo: UserAuditTrailRepo
        val client = testServiceClient()
        val call = mockk<ApplicationCall>()

        @BeforeClass
        @JvmStatic
        fun setup() {
            repo = UserAuditTrailRepo()
            every { call.callId } returns "request-id-1234"
        }
    }
}
