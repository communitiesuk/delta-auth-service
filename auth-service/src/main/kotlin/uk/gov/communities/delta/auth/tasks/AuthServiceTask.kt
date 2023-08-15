package uk.gov.communities.delta.auth.tasks

import kotlinx.coroutines.slf4j.MDCContext
import kotlinx.coroutines.withContext
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import java.time.Instant
import java.util.*
import kotlin.coroutines.coroutineContext
import kotlin.time.Duration

abstract class AuthServiceTask(val name: String, val every: Duration) {
    protected val logger: Logger = LoggerFactory.getLogger(this::class.java)

    suspend fun run() {
        val executionId = UUID.randomUUID()
        val currentMdcMap = coroutineContext[MDCContext.Key]?.contextMap ?: emptyMap()
        val mdcContext = MDCContext(
            currentMdcMap + mapOf(
                "taskName" to name,
                "taskStartTime" to Instant.now().toString(),
                "executionId" to executionId.toString(),
            )
        )
        withContext(mdcContext) {
            try {
                logger.info("Starting task")
                execute()
                logger.info("Task complete")
            } catch (e: Exception) {
                logger.error("Task failed with exception", e)
            }
        }
    }

    protected abstract suspend fun execute()
}
