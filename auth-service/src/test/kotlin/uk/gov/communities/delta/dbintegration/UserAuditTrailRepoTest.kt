package uk.gov.communities.delta.dbintegration

import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.BeforeClass
import org.junit.Test
import uk.gov.communities.delta.auth.repositories.UserAuditTrailRepo
import java.time.Instant
import kotlin.test.assertEquals
import kotlin.test.assertNull

class UserAuditTrailRepoTest {
    @Test
    fun testRetrievesAuditValues() {
        testDbPool.useConnectionBlocking("test_login_audit") {
            val audit = repo.getAuditForUser(it, "some.user!audit-test.com")
            assertEquals(2, audit.size)
            assertEquals("some.user!audit-test.com", audit[1].userCn)
            assertEquals("requestId", audit[1].requestId)
            assertNull(audit[1].editingUserCn)
            assertEquals(UserAuditTrailRepo.AuditAction.FORM_LOGIN, audit[1].action)
            assertEquals("value", audit[1].actionData.jsonObject["key"]!!.jsonPrimitive.content)
        }
    }

    @Test
    fun testOtherUserAuditIsEmpty() {
        testDbPool.useConnectionBlocking("test_login_audit") {
            assertEquals(0, repo.getAuditForUser(it, "other.user!audit-test.com").size)
        }
    }

    @Test
    fun testPagination() {
        testDbPool.useConnectionBlocking("test_login_audit") {
            val firstPage = repo.getAuditForUser(it, "some.user!audit-test.com", Pair(1, 0))
            val secondPage = repo.getAuditForUser(it, "some.user!audit-test.com", Pair(1, 1))
            val thirdPage = repo.getAuditForUser(it, "some.user!audit-test.com", Pair(1, 2))
            assertEquals(UserAuditTrailRepo.AuditAction.RESET_PASSWORD_EMAIL, firstPage.single().action)
            assertEquals(UserAuditTrailRepo.AuditAction.FORM_LOGIN, secondPage.single().action)
            assertEquals(0, thirdPage.size)
        }
    }

    @Test
    fun testRecordCount() {
        testDbPool.useConnectionBlocking("test_login_audit") {
            assertEquals(2, repo.getAuditItemCount(it, "some.user!audit-test.com"))
        }
    }

    @Test
    fun testAllUserAudit() {
        testDbPool.useConnectionBlocking("test_login_audit") { conn ->
            val all = repo.getAuditForAllUsers(conn, Instant.now().minusSeconds(60), Instant.now().plusSeconds(10))
            assertEquals(2, all.filter { it.userCn == "some.user!audit-test.com" }.size)
            val allAfterNow = repo.getAuditForAllUsers(conn, Instant.now().plusSeconds(60), Instant.now().plusSeconds(100))
            assertEquals(0, allAfterNow.size)
        }
    }

    companion object {
        lateinit var repo: UserAuditTrailRepo

        @BeforeClass
        @JvmStatic
        fun setup() {
            repo = UserAuditTrailRepo()
            testDbPool.useConnectionBlocking("test_login_audit") {
                assertEquals(0, repo.getAuditForUser(it, "some.user!audit-test.com").size)

                repo.insertAuditRow(
                    it,
                    UserAuditTrailRepo.AuditAction.FORM_LOGIN,
                    "some.user!audit-test.com",
                    null,
                    "requestId",
                    "{\"key\": \"value\"}"
                )
                it.commit() // So that the next row has a different timestamp, and we can check ordering (newest first)
                Thread.sleep(1)
                repo.insertAuditRow(
                    it,
                    UserAuditTrailRepo.AuditAction.RESET_PASSWORD_EMAIL,
                    "some.user!audit-test.com",
                    null,
                    "requestId2",
                    "{}"
                )
                it.commit()
            }
        }
    }
}
