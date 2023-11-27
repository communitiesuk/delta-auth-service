package uk.gov.communities.delta.dbintegration

import io.ktor.server.application.*
import io.ktor.server.plugins.callid.*
import io.ktor.test.dispatcher.*
import io.mockk.every
import io.mockk.mockk
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.BeforeClass
import org.junit.Test
import uk.gov.communities.delta.auth.config.AzureADSSOClient
import uk.gov.communities.delta.auth.services.UserAuditService
import uk.gov.communities.delta.auth.repositories.UserAuditTrailRepo
import uk.gov.communities.delta.helper.testServiceClient
import kotlin.test.assertEquals
import kotlin.test.assertNull

class UserAuditServiceTest {
    @Test
    fun testUserLoginAudit() = testSuspend {
        assertEquals(0, service.getAuditForUser("login.user!example.com").size)

        service.userFormLoginAudit("login.user!example.com", call)

        val audit = service.getAuditForUser("login.user!example.com")
        assertEquals(1, audit.size)
        assertEquals("login.user!example.com", audit[0].userCn)
        assertEquals(call.callId, audit[0].requestId)
        assertNull(audit[0].editingUserCn)
        assertEquals(UserAuditTrailRepo.AuditAction.FORM_LOGIN, audit[0].action)
    }

    @Test
    fun testSSOLoginAudit() = testSuspend {
        service.userSSOLoginAudit(
            "sso.user!example.com",
                AzureADSSOClient("sso-id", "", "", "", "@example.com"),
                "az-123", call,
            )

        val audit = service.getAuditForUser("sso.user!example.com")
        assertEquals(1, audit.size)
        assertEquals("sso.user!example.com", audit[0].userCn)
        assertEquals(call.callId, audit[0].requestId)
        assertNull(audit[0].editingUserCn)
        assertEquals(UserAuditTrailRepo.AuditAction.SSO_LOGIN, audit[0].action)
        assertEquals("az-123", audit[0].actionData.jsonObject["azureUserObjectId"]!!.jsonPrimitive.content)
    }

    companion object {
        lateinit var service: UserAuditService
        val client = testServiceClient()
        val call = mockk<ApplicationCall>()

        @BeforeClass
        @JvmStatic
        fun setup() {
            val repo = UserAuditTrailRepo()
            service = UserAuditService(repo, testDbPool)
            every { call.callId } returns "request-id-1234"
        }
    }
}
