package uk.gov.communities.delta.auth.tasks

import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import uk.gov.communities.delta.auth.Injection
import uk.gov.communities.delta.auth.config.Env
import kotlin.time.Duration.Companion.minutes

/*
 * Separate entrypoint for running tasks, used by entrypoint.sh when RUN_TASK is set.
 * Note that currently entrypoint.sh doesn't set up the LDAPS CA when running this entrypoint,
 * change that if you need to use LDAP for a task.
 */
fun main() {
    val injection = Injection.startupInitFromEnvironment()
    val allTasks = injection.tasksMap()
    val taskName = Env.getRequired("RUN_TASK")
    val task = allTasks[taskName] ?: throw Exception("Unknown task '$taskName'")
    val taskRunner = injection.taskRunner()

    runBlocking {
        withTimeout(10.minutes) {
            taskRunner.runTask(task)
        }
    }
}
