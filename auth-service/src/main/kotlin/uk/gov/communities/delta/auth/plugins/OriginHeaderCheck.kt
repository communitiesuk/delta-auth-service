package uk.gov.communities.delta.auth.plugins

import io.ktor.http.*
import io.ktor.server.application.*
import io.ktor.server.plugins.callid.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.ktor.server.thymeleaf.*
import org.slf4j.LoggerFactory
import uk.gov.communities.delta.auth.config.DeltaConfig

private val logger = LoggerFactory.getLogger("uk.gov.communities.delta.auth.plugins.OriginHeaderCheck")

private val safeMethods = listOf(HttpMethod.Get, HttpMethod.Head, HttpMethod.Options)

fun originHeaderCheck(serviceUrl: String, deltaConfig: DeltaConfig) = createRouteScopedPlugin("OriginHeaderCheck") {
    on(BeforeCall) { call, proceed ->
        if (safeMethods.contains(call.request.httpMethod)) return@on proceed()

        val origin = call.request.headers["Origin"]
        if (origin != serviceUrl) {
            logger.warn(
                "Origin header check failure, expected '{}' got '{}' for user agent {}",
                serviceUrl,
                origin,
                call.request.headers["User-Agent"]
            )

            try {
                call.respond(
                    HttpStatusCode.BadRequest,
                    ThymeleafContent(
                        "error.html", mapOf(
                            "deltaUrl" to deltaConfig.deltaWebsiteUrl,
                            "title" to "Error | Delta",
                            "heading" to "Error",
                            "message" to "Origin header check failed. If you are using Internet Explorer please try another browser",
                            "requestId" to call.callId!!,
                            "isProduction" to deltaConfig.isProduction
                        )
                    )
                )
            } catch (e: Exception) {
                application.log.error("Exception occurred processing origin header check error page", e)
                if (!call.response.isCommitted) {
                    call.respondText("Failed to render error page. Request id ${call.callId}")
                }
            }
        }
    }
}
