package uk.gov.communities.delta.dbintegration

import io.ktor.server.application.*
import io.ktor.server.plugins.callid.*
import io.ktor.test.dispatcher.*
import io.mockk.every
import io.mockk.mockk
import org.junit.BeforeClass
import org.junit.Test
import uk.gov.communities.delta.auth.services.UserAuditTrailRepo
import uk.gov.communities.delta.helper.testServiceClient
import kotlin.test.assertEquals

class UserAuditTrailRepoTest {
    @Test
    fun testUserLoginAudit() {
        testDbPool.useConnectionBlocking("test_login_audit") {
            assertEquals(0, repo.getAuditForUser(it, "some.user!example.com").size)
            repo.userFormLoginAudit(it, "some.user!example.com", call)
            assertEquals(1, repo.getAuditForUser(it, "some.user!example.com").size)
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
