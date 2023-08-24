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

    @Test
    fun deleteOldAuthCodesTest() = testSuspend {
        val newCode =
            authorizationCodeService.generateAndStore("DeleteOldAuthCodesTest-new-user", testServiceClient(), "trace")
        time = { Instant.now().minus(2, ChronoUnit.DAYS) }
        authorizationCodeService.generateAndStore("DeleteOldAuthCodesTest-old-user", testServiceClient(), "old-trace")
        time = { Instant.now() }

        testDbPool.useConnection {
            assertEquals(
                1,
                countOldAuthCodes()
            )
        }

        underTest.execute()

        testDbPool.useConnection {
            assertEquals(
                0,
                countOldAuthCodes()
            )
        }
        assertNotNull(authorizationCodeService.lookupAndInvalidate(newCode.code, testServiceClient()))
    }

    private fun countOldAuthCodes(): Int {
        return testDbPool.useConnection {
            val resultSet = it.createStatement()
                .executeQuery("SELECT COUNT(*) FROM authorization_code WHERE username = 'DeleteOldAuthCodesTest-old-user'")
            resultSet.next()
            resultSet.getInt(1)
        }
    }
}
