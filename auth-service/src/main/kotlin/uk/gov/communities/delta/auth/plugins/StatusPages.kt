package uk.gov.communities.delta.auth.plugins

import io.ktor.http.*
import io.ktor.server.application.*
import io.ktor.server.plugins.callid.*
import io.ktor.server.plugins.statuspages.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.ktor.server.thymeleaf.*
import org.slf4j.LoggerFactory
import uk.gov.communities.delta.auth.config.AzureADSSOConfig
import uk.gov.communities.delta.auth.config.DeltaConfig

private const val apiRoutePrefix = "/auth-internal/"

fun Application.configureStatusPages(deltaWebsiteUrl: String, ssoConfig: AzureADSSOConfig) {
    val logger = LoggerFactory.getLogger("Delta.StatusPages")
    install(StatusPages) {
        // Currently only the login page is rate limited so always renders the login page for status "TooManyRequests"
        status(HttpStatusCode.TooManyRequests) { call, _ ->
            call.respond(ThymeleafContent("delta-login",
                mapOf(
                    "deltaUrl" to DeltaConfig.fromEnv().deltaWebsiteUrl,
                    "errorMessage" to "Too many requests from your location, please try again in a few minutes.",
                    "ssoClients" to ssoConfig.ssoClients.filter { it.buttonText != null },
                ))
            )
        }
        for (s in statusErrorPageDefinitions) {
            status(s.key) { call, _ ->
                call.respondStatusPage(s.value, deltaWebsiteUrl)
            }
        }
        exception(UserVisibleServerError::class) { call, ex ->
            logger.error("StatusPages user visible error", ex)
            val errorPage = StatusErrorPageDefinition(
                HttpStatusCode.InternalServerError,
                "user_visible_server_error",
                "DELTA | ${ex.title}",
                ex.title,
                ex.userVisibleMessage,
                showServiceDeskMessage = true,
            )
            call.respondStatusPage(errorPage, deltaWebsiteUrl)
        }
        exception(HttpNotFoundException::class) { call, ex ->
            logger.error("StatusPages NotFoundException", ex)
            call.respondStatusPage(statusErrorPageDefinitions[HttpStatusCode.NotFound]!!, deltaWebsiteUrl)
        }
    }
}

open class UserVisibleServerError(
    exceptionMessage: String,
    val userVisibleMessage: String,
    val title: String = "Error"
) :
    Exception(exceptionMessage)

class HttpNotFoundException(message: String) : Exception(message)

private val statusErrorPageDefinitions = mapOf(
    HttpStatusCode.NotFound to StatusErrorPageDefinition(
        HttpStatusCode.NotFound,
        "not_found",
        "DELTA | Not Found",
        "Page not found",
        "This page does not exist"
    ),
    HttpStatusCode.InternalServerError to StatusErrorPageDefinition(
        HttpStatusCode.InternalServerError,
        "internal_server_error",
        "DELTA | Error",
        "Error",
        "Something went wrong",
        true
    ),
)

private suspend fun ApplicationCall.respondStatusPage(statusError: StatusErrorPageDefinition, deltaWebsiteUrl: String) {
    if (request.path().startsWith(apiRoutePrefix)) {
        apiErrorResponse(statusError)
    } else {
        userFacingErrorResponse(statusError, deltaWebsiteUrl)
    }
}

private suspend fun ApplicationCall.apiErrorResponse(statusError: StatusErrorPageDefinition) {
    respond(statusError.statusCode, mapOf("error" to statusError.jsonError))
}

private suspend fun ApplicationCall.userFacingErrorResponse(
    statusError: StatusErrorPageDefinition,
    deltaWebsiteUrl: String,
) {
    try {
        respond(
            statusError.statusCode,
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
        application.log.error("Exception occurred processing status page for status {}", statusError.statusCode, e)
        if (!response.isCommitted) {
            respondText("Failed to render error page. Request id $callId")
        }
    }
}

private data class StatusErrorPageDefinition(
    val statusCode: HttpStatusCode,
    val jsonError: String,
    val userErrorPageTitle: String,
    val userErrorPageHeading: String,
    val userErrorPageMessage: String,
    val showServiceDeskMessage: Boolean = false,
)
