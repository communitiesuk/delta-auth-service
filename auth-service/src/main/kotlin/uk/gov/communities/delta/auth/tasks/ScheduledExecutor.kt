package uk.gov.communities.delta.auth.tasks

import kotlinx.coroutines.runBlocking
import org.slf4j.LoggerFactory
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

fun startScheduler(tasks: List<AuthServiceTask>) {
    val logger = LoggerFactory.getLogger("Application.Tasks")
    val scheduler = Executors.newScheduledThreadPool(1)
    for (task in tasks) {
        scheduler.scheduleAtFixedRate(
            {
                runBlocking {
                    task.run()
                }
            },
            task.every.inWholeSeconds,
            task.every.inWholeSeconds,
            TimeUnit.SECONDS
        )
        logger.info("Scheduled task {} to run every {} seconds", task.name, task.every.inWholeSeconds)
    }
}
