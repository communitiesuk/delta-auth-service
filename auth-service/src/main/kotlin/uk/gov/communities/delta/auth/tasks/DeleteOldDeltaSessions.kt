package uk.gov.communities.delta.auth.tasks

import uk.gov.communities.delta.auth.services.DbPool
import java.sql.Timestamp
import java.time.Instant
import java.time.temporal.ChronoUnit
import kotlin.time.Duration.Companion.hours

class DeleteOldDeltaSessions(private val db: DbPool) : AuthServiceTask("DeleteOldDeltaSessions", 12.hours) {
    override suspend fun execute() {
        db.useConnection {
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
