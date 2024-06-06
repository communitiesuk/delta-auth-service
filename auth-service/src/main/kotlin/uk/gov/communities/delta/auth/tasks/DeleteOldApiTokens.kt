package uk.gov.communities.delta.auth.tasks

import org.slf4j.LoggerFactory
import uk.gov.communities.delta.auth.repositories.DbPool
import java.sql.Timestamp
import java.time.Instant
import java.time.temporal.ChronoUnit

class DeleteOldApiTokens(private val db: DbPool) : AuthServiceTask("DeleteOldApiTokens")  {
    private val logger = LoggerFactory.getLogger(javaClass)

    // Tasks are run separately anyway
    @Suppress("BlockingMethodInNonBlockingContext")
    override suspend fun execute() {
        db.useConnectionBlocking("DeleteOldApiTokens") {
            val stmt = it.prepareStatement(
                "DELETE FROM api_tokens WHERE created_at < ?"
            )
            stmt.setTimestamp(1, Timestamp.from(Instant.now().minus(1, ChronoUnit.DAYS)))
            val result = stmt.executeUpdate()
            it.commit()
            logger.info("Deleted {} old api tokens", result)
        }
    }
}
