package uk.gov.communities.delta.auth.controllers.internal

import io.ktor.http.*
import io.ktor.server.application.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import kotlinx.coroutines.*
import kotlinx.coroutines.slf4j.MDCContext
import net.logstash.logback.argument.StructuredArguments.keyValue
import org.slf4j.LoggerFactory
import uk.gov.communities.delta.auth.plugins.HttpNotFoundException
import uk.gov.communities.delta.auth.tasks.AuthServiceTask

class TasksController(private val tasks: Map<String, AuthServiceTask>) {
    private val logger = LoggerFactory.getLogger(javaClass)
    private val job = SupervisorJob()
    private val scope = CoroutineScope(Dispatchers.IO + job)

    fun route(route: Route) {
        route.post("/{taskName}") {
            runTask(call.parameters["taskName"]!!)
            call.respond(HttpStatusCode.Accepted)
        }
    }

    private fun runTask(taskName: String) {
        val task = tasks[taskName] ?: throw HttpNotFoundException("Task $taskName does not exist")
        logger.info("Dispatching task {} due to request", keyValue("taskName", taskName))

        (scope + MDCContext()).launch {
            task.run()
        }
    }
}
