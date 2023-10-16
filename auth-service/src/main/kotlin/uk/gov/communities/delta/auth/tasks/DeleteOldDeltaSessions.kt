package uk.gov.communities.delta.auth.tasks

import org.slf4j.LoggerFactory
import uk.gov.communities.delta.auth.services.DbPool
import java.sql.Timestamp
import java.time.Instant
import java.time.temporal.ChronoUnit

class DeleteOldDeltaSessions(private val db: DbPool) :
    AuthServiceTask("DeleteOldDeltaSessions") {
    private val logger = LoggerFactory.getLogger(javaClass)

    // Tasks are run separately anyway
    @Suppress("BlockingMethodInNonBlockingContext")
    override suspend fun execute() {
        db.useConnectionBlocking("DeleteOldDeltaSessions") {
            val stmt = it.prepareStatement(
                "DELETE FROM delta_session WHERE created_at < ?"
            )
            stmt.setTimestamp(1, Timestamp.from(Instant.now().minus(10, ChronoUnit.DAYS)))
            val result = stmt.executeUpdate()
            it.commit()
            logger.info("Deleted {} old delta sessions", result)
        }
    }
}
