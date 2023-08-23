package uk.gov.communities.delta.auth.tasks

import io.micrometer.core.instrument.MeterRegistry
import io.micrometer.core.instrument.Tag
import kotlinx.coroutines.slf4j.MDCContext
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import java.time.Instant
import java.util.*
import kotlin.coroutines.coroutineContext
import kotlin.time.Duration.Companion.minutes

class TaskRunner(private val meterRegistry: MeterRegistry) {
    private val logger: Logger = LoggerFactory.getLogger(javaClass)

    private val allTasksSuccessCounter = meterRegistry.counter("tasks.success")
    private val allTasksFailureCounter = meterRegistry.counter("tasks.failure")

    suspend fun runTask(task: AuthServiceTask) {
        val executionId = UUID.randomUUID()
        val currentMdcMap = coroutineContext[MDCContext.Key]?.contextMap ?: emptyMap()
        val mdcContext = MDCContext(
            currentMdcMap + mapOf(
                "taskName" to task.name,
                "taskStartTime" to Instant.now().toString(),
                "executionId" to executionId.toString(),
            )
        )

        withContext(mdcContext) {
            withTimeout(10.minutes) {
                executeTaskWithMetrics(task)
            }
        }
    }

    private suspend fun executeTaskWithMetrics(task: AuthServiceTask) {
        val taskSpecificSuccessCounter = meterRegistry.counter("tasks.success", listOf(Tag.of("taskName", task.name)))
        val taskSpecificFailureCounter = meterRegistry.counter("tasks.failure", listOf(Tag.of("taskName", task.name)))

        try {
            logger.info("Starting task")
            task.execute()
            logger.info("Task complete")
            allTasksSuccessCounter.increment()
            taskSpecificSuccessCounter.increment()
        } catch (e: Exception) {
            logger.error("Task failed with exception", e)
            allTasksFailureCounter.increment()
            taskSpecificFailureCounter.increment()
            throw TaskFailureException(task.name, e)
        }
    }

    class TaskFailureException(taskName: String, cause: Exception) :
        Exception("Task $taskName failed with exception", cause)
}
