package uk.gov.communities.delta.tasks

import io.ktor.test.dispatcher.*
import org.junit.Test
import uk.gov.communities.delta.auth.services.AuthorizationCodeService
import uk.gov.communities.delta.auth.tasks.DeleteOldAuthCodes
import uk.gov.communities.delta.auth.utils.TimeSource
import uk.gov.communities.delta.dbintegration.testDbPool
import uk.gov.communities.delta.helper.testServiceClient
import java.time.Instant
import java.time.temporal.ChronoUnit
import java.util.*
import kotlin.test.assertEquals
import kotlin.test.assertNotNull

class DeleteOldAuthCodesTest {
    private var time = { Instant.now() }
    private val timeSource = object : TimeSource {
        override fun now(): Instant {
            return time()
        }
    }
    private val underTest = DeleteOldAuthCodes(testDbPool)
    private val authorizationCodeService = AuthorizationCodeService(testDbPool, timeSource)
    private val oldUUID = UUID.randomUUID()
    private val newUUID = UUID.randomUUID()

    @Test
    fun deleteOldAuthCodesTest() = testSuspend {
        val newCode =
            authorizationCodeService.generateAndStore(newUUID, testServiceClient(), "trace", false)
        time = { Instant.now().minus(2, ChronoUnit.DAYS) }
        authorizationCodeService.generateAndStore(oldUUID, testServiceClient(), "old-trace", false)
        time = { Instant.now() }

        testDbPool.useConnectionBlocking("test") {
            assertEquals(
                1,
                countOldAuthCodes()
            )
        }

        underTest.execute()

        testDbPool.useConnectionBlocking("test") {
            assertEquals(
                0,
                countOldAuthCodes()
            )
        }
        assertNotNull(authorizationCodeService.lookupAndInvalidate(newCode.code, testServiceClient()))
    }

    private fun countOldAuthCodes(): Int {
        return testDbPool.useConnectionBlocking("test") {
            val stmt = it.prepareStatement("SELECT COUNT(*) FROM authorization_code WHERE user_guid = ?")
            stmt.setObject(1, oldUUID)
            val resultSet = stmt.executeQuery()
            resultSet.next()
            resultSet.getInt(1)
        }
    }
}
