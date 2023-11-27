package uk.gov.communities.delta.dbintegration

import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.BeforeClass
import org.junit.Test
import uk.gov.communities.delta.auth.repositories.UserAuditTrailRepo
import kotlin.test.assertEquals
import kotlin.test.assertNull

class UserAuditTrailRepoTest {
    @Test
    fun testUserAudit() {
        testDbPool.useConnectionBlocking("test_login_audit") {
            assertEquals(0, repo.getAuditForUser(it, "some.user!example.com").size)

            repo.insertAuditRow(
                it,
                UserAuditTrailRepo.AuditAction.FORM_LOGIN,
                "some.user!example.com",
                null,
                "requestId",
                "{\"key\": \"value\"}"
            )

            val audit = repo.getAuditForUser(it, "some.user!example.com")
            assertEquals(1, audit.size)
            assertEquals("some.user!example.com", audit[0].userCn)
            assertEquals("requestId", audit[0].requestId)
            assertNull(audit[0].editingUserCn)
            assertEquals(UserAuditTrailRepo.AuditAction.FORM_LOGIN, audit[0].action)
            assertEquals("value", audit[0].actionData.jsonObject["key"]!!.jsonPrimitive.content)

            assertEquals(0, repo.getAuditForUser(it, "other.user!example.com").size)

            it.rollback()
        }
    }

    companion object {
        lateinit var repo: UserAuditTrailRepo

        @BeforeClass
        @JvmStatic
        fun setup() {
            repo = UserAuditTrailRepo()
        }
    }
}
