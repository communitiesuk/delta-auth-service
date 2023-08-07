package uk.gov.communities.delta.auth.plugins

import io.ktor.http.*
import io.ktor.server.application.*
import io.ktor.server.plugins.callid.*
import io.ktor.server.plugins.statuspages.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.ktor.server.thymeleaf.*
import uk.gov.communities.delta.auth.config.DeltaConfig

private const val apiRoutePrefix = "/auth-internal/"

fun Application.configureStatusPages(deltaWebsiteUrl: String) {
    install(StatusPages) {
        // Currently only the login page is rate limited so always renders the login page for status "TooManyRequests"
        status(HttpStatusCode.TooManyRequests) { call, _ ->
            call.respond(ThymeleafContent("delta-login",
                mapOf(
                    "deltaUrl" to DeltaConfig.fromEnv().deltaWebsiteUrl,
                    "errorMessage" to "Too many requests from your location, please try again in a few minutes.",
                )))
        }
        for (s in statusErrorPageDefinitions) {
            status(s.key) { call, status ->
                if (call.request.path().startsWith(apiRoutePrefix)) {
                    call.apiErrorResponse(status, s.value)
                } else {
                    call.userFacingErrorResponse(status, s.value, deltaWebsiteUrl)
                }
            }
        }
    }
}

private val statusErrorPageDefinitions = mapOf(
    HttpStatusCode.NotFound to StatusErrorPageDefinition(
        "not_found",
        "DELTA | Not Found",
        "Page not found",
        "This page does not exist"
    ),
    HttpStatusCode.InternalServerError to StatusErrorPageDefinition(
        "internal_server_error",
        "DELTA | Error",
        "Error",
        "Something went wrong",
        true
    ),
)

private suspend fun ApplicationCall.apiErrorResponse(status: HttpStatusCode, statusError: StatusErrorPageDefinition) {
    respond(status, mapOf("error" to statusError.jsonError))
}

private suspend fun ApplicationCall.userFacingErrorResponse(
    status: HttpStatusCode,
    statusError: StatusErrorPageDefinition,
    deltaWebsiteUrl: String,
) {
    try {
        respond(
            status,
            ThymeleafContent(
                "error.html", mapOf(
                    "deltaUrl" to deltaWebsiteUrl,
                    "title" to statusError.userErrorPageTitle,
                    "heading" to statusError.userErrorPageHeading,
                    "message" to statusError.userErrorPageMessage,
                    "requestId" to if (statusError.showServiceDeskMessage) callId ?: "" else "",
                )
            )
        )
    } catch (e: Exception) {
        application.log.error("Exception occurred processing status page for status {}", status, e)
        if (!response.isCommitted) {
            respondText("Failed to render error page. Request id $callId")
        }
    }
}

private data class StatusErrorPageDefinition(
    val jsonError: String,
    val userErrorPageTitle: String,
    val userErrorPageHeading: String,
    val userErrorPageMessage: String,
    val showServiceDeskMessage: Boolean = false,
)
