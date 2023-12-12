package uk.gov.communities.delta.auth.plugins

import io.ktor.http.*
import io.ktor.server.application.*
import io.ktor.server.plugins.callid.*
import io.ktor.server.plugins.statuspages.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.ktor.server.thymeleaf.*
import net.logstash.logback.argument.StructuredArguments.keyValue
import org.slf4j.LoggerFactory
import uk.gov.communities.delta.auth.config.AzureADSSOConfig
import uk.gov.communities.delta.auth.config.DeltaConfig

private const val apiRoutePrefix = "/auth-internal/"
private const val tooManyRequestsErrorMessage =
    "Too many requests from your location, please try again in a few minutes."

fun Application.configureStatusPages(deltaWebsiteUrl: String, ssoConfig: AzureADSSOConfig, deltaConfig: DeltaConfig) {
    val logger = LoggerFactory.getLogger("Delta.StatusPages")
    install(StatusPages) {
        // Currently login page and registration pages are rate limited, if path not recognised defaults to login page for status "TooManyRequests"
        status(HttpStatusCode.TooManyRequests) { call, _ ->
            call.addSecurityHeaders()
            if (call.request.path().contains("/register"))
                try {
                    call.respond(
                        ThymeleafContent(
                            "register-user-form",
                            mapOf(
                                "deltaUrl" to deltaConfig.deltaWebsiteUrl,
                                "allErrors" to arrayListOf(arrayListOf(tooManyRequestsErrorMessage, "#")),
                            )
                        )
                    )
                } catch (e: Exception) {
                    logger.error("Failed to render Delta registration form page after rate limit", e)
                    call.respondText("Failed to render registration form page after reaching rate limit. Request id ${call.callId}")
                }
            else if (call.request.path().contains("/set-password"))
                try {
                    call.respond(
                        ThymeleafContent(
                            "password-form",
                            mapOf(
                                "deltaUrl" to deltaConfig.deltaWebsiteUrl,
                                "message" to tooManyRequestsErrorMessage,
                            )
                        )
                    )
                } catch (e: Exception) {
                    logger.error("Failed to render Delta set password form page after rate limit", e)
                    call.respondText("Failed to render set password form page after reaching rate limit. Request id ${call.callId}")
                }
            else if (call.request.path().contains("/reset-password"))
                try {
                    call.respond(
                        ThymeleafContent(
                            "password-form",
                            mapOf(
                                "deltaUrl" to deltaConfig.deltaWebsiteUrl,
                                "message" to tooManyRequestsErrorMessage,
                            )
                        )
                    )
                } catch (e: Exception) {
                    logger.error("Failed to render Delta reset password form page after rate limit", e)
                    call.respondText("Failed to render reset password form page after reaching rate limit. Request id ${call.callId}")
                }
            else if (call.request.path().contains("/forgot-password"))
                try {
                    call.respond(
                        ThymeleafContent(
                            "forgot-password",
                            mapOf(
                                "deltaUrl" to deltaConfig.deltaWebsiteUrl,
                                "message" to tooManyRequestsErrorMessage,
                            )
                        )
                    )
                } catch (e: Exception) {
                    logger.error("Failed to render Delta forgot password form page after rate limit", e)
                    call.respondText("Failed to render forgot password form page after reaching rate limit. Request id ${call.callId}")
                }
            else try {
                call.respond(
                    ThymeleafContent(
                        "delta-login",
                        mapOf(
                            "deltaUrl" to deltaConfig.deltaWebsiteUrl,
                            "errorMessage" to tooManyRequestsErrorMessage,
                            "ssoClients" to ssoConfig.ssoClients.filter { it.buttonText != null },
                        )
                    )
                )
            } catch (e: Exception) {
                logger.error("Failed to render Delta login page after rate limit", e)
                call.respondText("Failed to render login page after reaching rate limit. Request id ${call.callId}")
            }
        }
        for (s in statusErrorPageDefinitions) {
            status(s.key) { call, _ ->
                call.addSecurityHeaders()
                call.respondStatusPage(s.value, deltaWebsiteUrl)
            }
        }
        exception(UserVisibleServerError::class) { call, ex ->
            logger.warn("StatusPages user visible error {}", keyValue("errorCode", ex.errorCode), ex)
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
        exception(HttpNotFound404PageException::class) { call, ex ->
            logger.error("StatusPages NotFoundException", ex)
            call.respondStatusPage(statusErrorPageDefinitions[HttpStatusCode.NotFound]!!, deltaWebsiteUrl)
        }
        exception(ApiError::class) { call, ex ->
            logger.error("StatusPages API Error {}", keyValue("errorCode", ex.errorCode), ex)
            call.apiErrorResponse(ex)
        }
    }
}

open class ApiError(
    val statusCode: HttpStatusCode,
    val errorCode: String,
    val errorDescription: String,
    val userVisibleMessage: String? = null,
) : Exception("$errorCode ($statusCode) $errorDescription")

open class UserVisibleServerError(
    val errorCode: String,
    exceptionMessage: String,
    val userVisibleMessage: String,
    val title: String = "Error",
) :
    Exception("$errorCode $exceptionMessage")

class HttpNotFound404PageException(message: String) : Exception(message)

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
    respond(statusError.statusCode, mapOf(
        "error" to statusError.jsonError,
        "error_description" to "User visible error ${statusError.userErrorPageTitle}",
        "user_visible_error" to statusError.userErrorPageMessage,
    ))
}

private suspend fun ApplicationCall.apiErrorResponse(apiError: ApiError) {
    respond(apiError.statusCode, mapOf(
        "error" to apiError.errorCode,
        "error_description" to apiError.errorDescription,
        "user_visible_error" to apiError.userVisibleMessage,
    ))
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
