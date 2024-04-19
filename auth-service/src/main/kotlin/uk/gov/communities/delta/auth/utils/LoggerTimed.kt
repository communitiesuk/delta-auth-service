package uk.gov.communities.delta.auth.utils

import org.jetbrains.annotations.Blocking
import org.slf4j.Logger
import kotlin.coroutines.cancellation.CancellationException

@Suppress("DuplicatedCode")
@Blocking
fun <T> Logger.timed(
    action: String,
    logParams: (T) -> List<Pair<String, Any>> = { emptyList() },
    block: () -> T,
): T {
    val startTime = System.currentTimeMillis()
    val result = try {
        block()
    } catch (e: Exception) {
        this.atWarn()
            .addKeyValue("timedAction", action)
            .addKeyValue("durationMs", System.currentTimeMillis() - startTime)
            .log(if (e is CancellationException) "Timed action cancelled" else "Timed action failed", action, e)
        throw e
    }
    this.atInfo()
        .addKeyValue("timedAction", action)
        .addKeyValue("durationMs", System.currentTimeMillis() - startTime)
        .apply { logParams(result).forEach { addKeyValue(it.first, it.second) } }
        .log("Timed action {} complete", action)
    return result
}

@Suppress("DuplicatedCode")
suspend fun <T> Logger.timedSuspend(
    action: String,
    logParams: (T) -> List<Pair<String, Any>> = { emptyList() },
    block: suspend () -> T,
): T {
    val startTime = System.currentTimeMillis()
    val result = try {
        block()
    } catch (e: Exception) {
        this.atWarn()
            .addKeyValue("durationMs", System.currentTimeMillis() - startTime)
            .log("Timed action {} failed", action, e)
        throw e
    }
    this.atInfo()
        .addKeyValue("timedAction", action)
        .addKeyValue("durationMs", System.currentTimeMillis() - startTime)
        .apply { logParams(result).forEach { addKeyValue(it.first, it.second) } }
        .log("Timed action {} complete", action)
    return result
}
