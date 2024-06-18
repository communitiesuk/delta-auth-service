package uk.gov.communities.delta.auth.plugins.monitoring

import io.ktor.events.*
import io.ktor.http.*
import io.ktor.server.application.*
import io.ktor.server.application.hooks.*
import io.ktor.server.request.*
import io.ktor.util.*
import org.slf4j.LoggerFactory
import uk.gov.communities.delta.auth.plugins.ResponseSent

/*
 * Loosely based on the Ktor CallLogging plugin, but adapted for our requirements
 * https://github.com/ktorio/ktor/blob/main/ktor-server/ktor-server-plugins/ktor-server-call-logging/jvm/src/io/ktor/server/plugins/callloging/CallLogging.kt (Apache 2.0)
 */

private val CALL_START_TIME = AttributeKey<Long>("CallStartTime")

private fun ApplicationCall.processingTimeMillis(): Long {
    val startTime = attributes[CALL_START_TIME]
    return System.currentTimeMillis() - startTime
}

val CustomCallLogging = createApplicationPlugin("CallLogging") {
    on(CallSetup) { call ->
        call.attributes.put(CALL_START_TIME, System.currentTimeMillis())
    }

    on(ResponseSent) { call ->
        if (call.request.path() == "/health") return@on

        val status = call.response.status()?.value?.toString() ?: "Unhandled"
        val endpoint = "${call.request.httpMethod.value} ${call.request.path()}"
        logger.atInfo()
            .addKeyValue("endpoint", endpoint)
            .addKeyValue("requestContentType", call.request.contentType().contentType)
            .addKeyValue("responseContentType", call.response.headers[HttpHeaders.ContentType])
            .addKeyValue("requestContentLength", call.request.contentLength())
            .addKeyValue("responseContentLength", call.response.headers[HttpHeaders.ContentLength])
            .addKeyValue("durationMs", call.processingTimeMillis())
            .addKeyValue("responseStatus", status)
            .addKeyValue("LocationHeader", call.response.headers[HttpHeaders.Location])
            .log("Request to {}", call.request.uri)
    }

    setupApplicationLogging(application.environment.monitor)
}

private val logger = LoggerFactory.getLogger("Application.CallLogging")

private fun setupApplicationLogging(events: Events) {
    val starting: (Application) -> Unit = { logger.info("Application starting: {}", it) }
    val started: (Application) -> Unit = { logger.info("Application started: {}", it) }
    val stopping: (Application) -> Unit = { logger.info("Application stopping: {}", it) }
    var stopped: (Application) -> Unit = {}

    stopped = {
        logger.info("Application stopped: it")
        events.unsubscribe(ApplicationStarting, starting)
        events.unsubscribe(ApplicationStarted, started)
        events.unsubscribe(ApplicationStopping, stopping)
        events.unsubscribe(ApplicationStopped, stopped)
    }

    events.subscribe(ApplicationStarting, starting)
    events.subscribe(ApplicationStarted, started)
    events.subscribe(ApplicationStopping, stopping)
    events.subscribe(ApplicationStopped, stopped)
}
