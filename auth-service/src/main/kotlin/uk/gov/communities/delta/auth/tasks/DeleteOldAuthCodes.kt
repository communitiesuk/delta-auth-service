package uk.gov.communities.delta.auth.tasks

import uk.gov.communities.delta.auth.services.DbPool
import java.sql.Timestamp
import java.time.Instant
import java.time.temporal.ChronoUnit
import kotlin.time.Duration.Companion.hours

class DeleteOldAuthCodes(private val db: DbPool) : AuthServiceTask("DeleteOldAuthCodes", 12.hours) {
    override suspend fun execute() {
        db.useConnection {
            val stmt = it.prepareStatement(
                "DELETE FROM authorization_code WHERE created_at < ?"
            )
            stmt.setTimestamp(1, Timestamp.from(Instant.now().minus(1, ChronoUnit.DAYS)))
            val result = stmt.executeUpdate()
            it.commit()
            logger.info("Deleted {} old authorization codes", result)
        }
    }
}
