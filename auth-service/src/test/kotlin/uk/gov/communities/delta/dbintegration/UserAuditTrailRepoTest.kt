package uk.gov.communities.delta.dbintegration

import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.BeforeClass
import org.junit.Test
import uk.gov.communities.delta.auth.repositories.UserAuditTrailRepo
import uk.gov.communities.delta.auth.repositories.UserGUIDMapRepo
import uk.gov.communities.delta.helper.testLdapUser
import java.time.Instant
import kotlin.test.assertEquals
import kotlin.test.assertNull

class UserAuditTrailRepoTest {
    @Test
    fun testRetrievesAuditValues() {
        testDbPool.useConnectionBlocking("test_login_audit") {
            val audit = repo.getAuditForUser(it, user.getGUID())
            assertEquals(2, audit.size)
            assertEquals(user.getGUID(), audit[1].userGUID)
            assertEquals("requestId", audit[1].requestId)
            assertNull(audit[1].editingUserCN)
            assertEquals(UserAuditTrailRepo.AuditAction.FORM_LOGIN, audit[1].action)
            assertEquals("value", audit[1].actionData.jsonObject["key"]!!.jsonPrimitive.content)
        }
    }

    @Test
    fun testOtherUserAuditIsEmpty() {
        testDbPool.useConnectionBlocking("test_login_audit") {
            assertEquals(0, repo.getAuditForUser(it, otherUser.getGUID()).size)
        }
    }

    @Test
    fun testPagination() {
        testDbPool.useConnectionBlocking("test_login_audit") {
            val firstPage = repo.getAuditForUser(it, user.getGUID(), Pair(1, 0))
            val secondPage = repo.getAuditForUser(it, user.getGUID(), Pair(1, 1))
            val thirdPage = repo.getAuditForUser(it, user.getGUID(), Pair(1, 2))
            assertEquals(UserAuditTrailRepo.AuditAction.RESET_PASSWORD_EMAIL, firstPage.single().action)
            assertEquals(UserAuditTrailRepo.AuditAction.FORM_LOGIN, secondPage.single().action)
            assertEquals(0, thirdPage.size)
        }
    }

    @Test
    fun testRecordCount() {
        testDbPool.useConnectionBlocking("test_login_audit") {
            assertEquals(2, repo.getAuditItemCount(it, user.getGUID()))
        }
    }

    @Test
    fun testAllUserAudit() {
        testDbPool.useConnectionBlocking("test_login_audit") { conn ->
            val all = repo.getAuditForAllUsers(conn, Instant.now().minusSeconds(60), Instant.now().plusSeconds(10))
            assertEquals(4, all.size)
            assertEquals(2, all.filter { it.userGUID == user.getGUID() }.size)
            val allAfterNow = repo.getAuditForAllUsers(conn, Instant.now().plusSeconds(60), Instant.now().plusSeconds(100))
            assertEquals(0, allAfterNow.size)
        }
    }

    @Test
    fun testIsNewUserReturnsTrueWhenTrue() {
        testDbPool.useConnectionBlocking("check_is_new_user") {
            assertEquals(true, repo.checkIsNewUser(it,user.getGUID()))
        }
    }

    @Test
    fun testIsNewUserReturnsFalseAsNoUser() {
        testDbPool.useConnectionBlocking("check_is_new_user") {
            assertEquals(false, repo.checkIsNewUser(it,otherUser.getGUID()))
        }
    }

    @Test
    fun testIsNewUserReturnsFalseAsOldUser() {
        testDbPool.useConnectionBlocking("check_is_new_user") {
            assertEquals(false, repo.checkIsNewUser(it,oldUser.getGUID()))
        }
    }

    companion object {
        lateinit var repo: UserAuditTrailRepo
        private lateinit var userGUIDMapRepo: UserGUIDMapRepo
        private val user = testLdapUser(cn = "testUser")
        private val otherUser = testLdapUser(cn = "otherTestUser")
        private val oldUser = testLdapUser(cn = "oldTestUser")

        @BeforeClass
        @JvmStatic
        fun setup() {
            repo = UserAuditTrailRepo()
            userGUIDMapRepo = UserGUIDMapRepo()
            testDbPool.useConnectionBlocking("test_login_audit") {
                assertEquals(0, repo.getAuditForUser(it, user.getGUID()).size)

                repo.insertAuditRow(
                    it,
                    UserAuditTrailRepo.AuditAction.FORM_LOGIN,
                    user.getGUID(),
                    null,
                    "requestId",
                    "{\"key\": \"value\"}"
                )
                it.commit()
                repo.insertAuditRow(
                    it,
                    UserAuditTrailRepo.AuditAction.FORM_LOGIN,
                    oldUser.getGUID(),
                    null,
                    "requestId",
                    "{\"key\": \"value\"}"
                )
                it.commit()// So that the next row has a different timestamp, and we can check ordering (newest first)
                Thread.sleep(1)
                repo.insertAuditRow(
                    it,
                    UserAuditTrailRepo.AuditAction.RESET_PASSWORD_EMAIL,
                    user.getGUID(),
                    null,
                    "requestId2",
                    "{}"
                )
                repo.insertAuditRow(
                    it,
                    UserAuditTrailRepo.AuditAction.FORM_LOGIN,
                    oldUser.getGUID(),
                    null,
                    "requestId",
                    "{\"key\": \"value\"}"
                )
                userGUIDMapRepo.newUser(it, user)
                userGUIDMapRepo.newUser(it, otherUser)
                userGUIDMapRepo.newUser(it, oldUser)
                it.commit()
            }
        }
    }
}
