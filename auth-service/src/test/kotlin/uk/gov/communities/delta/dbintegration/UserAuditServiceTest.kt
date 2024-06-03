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
import uk.gov.communities.delta.auth.repositories.UserAuditTrailRepo
import uk.gov.communities.delta.auth.repositories.UserGUIDMapRepo
import uk.gov.communities.delta.auth.services.UserAuditService
import uk.gov.communities.delta.helper.testLdapUser
import uk.gov.communities.delta.helper.testServiceClient
import java.util.*
import kotlin.test.assertEquals
import kotlin.test.assertNull

class UserAuditServiceTest {
    @Test
    fun testUserLoginAudit() = testSuspend {
        val userGUID = UUID.fromString("aa11bb22-cc33-dd44-ee55-ff6677889900")
        val userCN = "auditServiceLoginTestCN"
        testDbPool.useConnectionBlocking("add_test_user_to_guid_map") {
            userGUIDMapRepo.newUser(it, testLdapUser(cn = userCN, javaUUIDObjectGuid = userGUID.toString()))
            it.commit()
            assertEquals(userGUID, userGUIDMapRepo.getGUIDForUserCNCaseSensitive(it, userCN))
        }
        assertEquals(0, service.getAuditForUser(userGUID).size)

        service.userFormLoginAudit(userGUID, call)

        val audit = service.getAuditForUser(userGUID)
        assertEquals(1, audit.size)
        assertEquals(userCN, audit[0].userCN)
        assertEquals(call.callId, audit[0].requestId)
        assertNull(audit[0].editingUserCN)
        assertEquals(UserAuditTrailRepo.AuditAction.FORM_LOGIN, audit[0].action)
    }

    @Test
    fun testSSOLoginAudit() = testSuspend {
        val userGUID = UUID.randomUUID()
        val userCN = "auditServiceSSOLoginTestCN"
        testDbPool.useConnectionBlocking("add_test_user_to_guid_map") {
            userGUIDMapRepo.newUser(it, testLdapUser(cn = userCN, javaUUIDObjectGuid = userGUID.toString()))
            it.commit()
            assertEquals(userGUID, userGUIDMapRepo.getGUIDForUserCNCaseSensitive(it, userCN))
        }
        service.userSSOLoginAudit(
            userGUID,
                AzureADSSOClient("sso-id", "", "", "", "@example.com"),
                "az-123", call,
            )

        val audit = service.getAuditForUser(userGUID)
        assertEquals(1, audit.size)
        assertEquals(userCN, audit[0].userCN)
        assertEquals(call.callId, audit[0].requestId)
        assertNull(audit[0].editingUserCN)
        assertEquals(UserAuditTrailRepo.AuditAction.SSO_LOGIN, audit[0].action)
        assertEquals("az-123", audit[0].actionData.jsonObject["azureUserObjectId"]!!.jsonPrimitive.content)
    }

    companion object {
        lateinit var service: UserAuditService
        val client = testServiceClient()
        val call = mockk<ApplicationCall>()
        private lateinit var userGUIDMapRepo: UserGUIDMapRepo


        @BeforeClass
        @JvmStatic
        fun setup() {
            val repo = UserAuditTrailRepo()
            service = UserAuditService(repo, testDbPool)
            userGUIDMapRepo = UserGUIDMapRepo()
            every { call.callId } returns "request-id-1234"
        }
    }
}
