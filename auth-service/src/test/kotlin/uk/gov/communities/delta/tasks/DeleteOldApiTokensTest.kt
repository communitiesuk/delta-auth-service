package uk.gov.communities.delta.tasks

import io.ktor.server.application.*
import io.ktor.test.dispatcher.*
import io.mockk.*
import org.junit.Before
import org.junit.BeforeClass
import org.junit.Test
import uk.gov.communities.delta.auth.services.DeltaApiTokenService
import uk.gov.communities.delta.auth.services.UserAuditService
import uk.gov.communities.delta.auth.tasks.DeleteOldApiTokens
import uk.gov.communities.delta.auth.tasks.DeleteOldAuthCodes
import uk.gov.communities.delta.auth.utils.TimeSource
import uk.gov.communities.delta.dbintegration.testDbPool
import java.time.Instant
import java.time.temporal.ChronoUnit
import kotlin.test.assertEquals

class DeleteOldApiTokensTest {
    @Test
    fun deleteOldApiTokensTest() = testSuspend {
        clearAllMocks()
        val userGuid = null
        val userClientId = "valid_id"
        val fakeCall = mockk<ApplicationCall>()
        coEvery { userAuditService.apiTokenCreationAudit(any(), any()) } just runs
        deltaApiTokenService.createAndStoreApiToken("newTokenUser", userClientId, userGuid, fakeCall)
        time = { Instant.now().minus(2, ChronoUnit.DAYS) }
        deltaApiTokenService.createAndStoreApiToken("oldTokenUser", userClientId, userGuid, fakeCall)
        time = { Instant.now() }

        testDbPool.useConnectionBlocking("test") {
            assertEquals(
                1,
                countApiTokens("oldTokenUser")
            )
            assertEquals(
                1,
                countApiTokens("newTokenUser")
            )
        }

        DeleteOldApiTokens(testDbPool).execute()

        testDbPool.useConnectionBlocking("test") {
            assertEquals(
                0,
                countApiTokens("oldTokenUser")
            )
            assertEquals(
                1,
                countApiTokens("newTokenUser")
            )
        }
    }

    private fun countApiTokens(userCn: String): Int {
        return testDbPool.useConnectionBlocking("test") {
            val stmt = it
                .prepareStatement("SELECT COUNT(*) FROM api_tokens WHERE created_by_user_cn = ?")
            stmt.setString(1, userCn)
            val resultSet = stmt.executeQuery()
            resultSet.next()
            resultSet.getInt(1)
        }
    }

    @Before
    fun resetMocks() {
        clearAllMocks()
        coEvery { userAuditService.apiTokenCreationAudit(any(), any()) } just runs
    }

    companion object {
        private var time = { Instant.now() }

        private val timeSource = object : TimeSource {
            override fun now(): Instant {
                return time()
            }
        }
        private val userAuditService = mockk<UserAuditService>()
        private val deltaApiTokenService = DeltaApiTokenService(testDbPool, timeSource, userAuditService)

        @BeforeClass
        @JvmStatic
        fun setup() {
            testDbPool.useConnectionBlocking("test_data_creation") {
                it.createStatement().execute("INSERT INTO api_clients (client_id, client_secret) VALUES ('valid_id', 'valid_secret')")
                it.commit()
            }
        }
    }
}
