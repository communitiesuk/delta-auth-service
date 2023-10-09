package uk.gov.communities.delta.auth.plugins

import io.ktor.http.*
import io.ktor.server.application.*
import io.ktor.server.request.*
import org.slf4j.LoggerFactory

private val logger = LoggerFactory.getLogger("uk.gov.communities.delta.auth.plugins.OriginHeaderCheck")

private val safeMethods = listOf(HttpMethod.Get, HttpMethod.Head, HttpMethod.Options)

fun originHeaderCheck(serviceUrl: String) = createRouteScopedPlugin("OriginHeaderCheck") {
    onCallRespond { call ->
        if (safeMethods.contains(call.request.httpMethod)) return@onCallRespond

        val origin = call.request.headers["Origin"]
        if (origin != serviceUrl) {
            logger.warn(
                "Origin header check failure, expected '{}' got '{}' for user agent {}",
                serviceUrl,
                origin,
                call.request.headers["User-Agent"]
            )
            throw InvalidOriginException("Origin header validation failed, expected '${serviceUrl}' got '$origin'")
        }
    }
}

class InvalidOriginException(message: String) : Exception(message)
