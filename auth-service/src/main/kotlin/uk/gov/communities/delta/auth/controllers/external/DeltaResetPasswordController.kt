package uk.gov.communities.delta.auth.controllers.external

import com.google.common.base.Strings
import io.ktor.http.*
import io.ktor.server.application.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import io.ktor.server.thymeleaf.*
import org.slf4j.LoggerFactory
import uk.gov.communities.delta.auth.config.DeltaConfig
import uk.gov.communities.delta.auth.plugins.ApiError
import uk.gov.communities.delta.auth.plugins.UserVisibleServerError
import uk.gov.communities.delta.auth.services.*
import uk.gov.communities.delta.auth.utils.PasswordChecker
import uk.gov.communities.delta.auth.utils.getUserFromCallParameters
import java.util.*

class DeltaResetPasswordController(
    private val deltaConfig: DeltaConfig,
    private val userService: UserService,
    private val resetPasswordTokenService: ResetPasswordTokenService,
    private val userLookupService: UserLookupService,
    private val emailService: EmailService,
    private val userAuditService: UserAuditService,
) {
    private val logger = LoggerFactory.getLogger(this.javaClass)
    private val passwordChecker = PasswordChecker()

    fun resetPasswordFormRoutes(route: Route) {
        route.post {
            resetPasswordPost(call)
        }
        route.get {
            resetPasswordGet(call)
        }
    }

    fun resetPasswordSuccessRoute(route: Route) {
        route.get {
            call.respondSuccessPage()
        }
    }

    fun resetPasswordExpired(route: Route) {
        route.post {
            resetPasswordExpiredPost(call)
        }
    }

    private suspend fun resetPasswordGet(call: ApplicationCall) {
        val user = getUserFromCallParameters( // TODO DT-976-2 - just get GUID once CN not needed
            call.request.queryParameters,
            userLookupService,
            "Something went wrong, please click the link in your latest password reset email or request a new one",
            "reset_password_get"
        )
        val token = call.request.queryParameters["token"].orEmpty()
        when (val tokenResult = resetPasswordTokenService.validateToken(token, user.cn, user.getGUID())) {
            is PasswordTokenService.NoSuchToken -> {
                logger.warn("Reset password get request with invalid token and/or userCN")
                throw ResetPasswordException("reset_password_no_token", "Reset password token did not exist")
            }

            is PasswordTokenService.ExpiredToken -> {
                logger.atWarn().addKeyValue("userGUID", user.getGUID())
                    .log("Reset password get request with expired token")
                val userEmail = userLookupService.lookupUserByGUID(user.getGUID()).email!!
                call.respondExpiredTokenPage(tokenResult, userEmail)
            }

            is PasswordTokenService.ValidToken -> {
                logger.atInfo().addKeyValue("userGUID", user.getGUID())
                    .log("Reset password get request with valid token")
                call.respondResetPasswordPage()
            }
        }
    }

    private suspend fun resetPasswordExpiredPost(call: ApplicationCall) {
        val formParameters = call.receiveParameters()
        val userGUID = UUID.fromString(formParameters["userGUID"]!!)
        val user = userLookupService.lookupUserByGUID(userGUID)
        val token = formParameters["token"]!!
        val tokenResult = resetPasswordTokenService.consumeTokenIfValid(token, user.cn, userGUID)
        if (tokenResult is PasswordTokenService.ExpiredToken) {
            logger.atInfo().addKeyValue("userCN", user.cn).log("Sending new reset password link (after expiry)")
            emailService.sendResetPasswordEmail(
                userLookupService.lookupUserByGUID(userGUID),
                resetPasswordTokenService.createToken(user.cn, userGUID),
                null,
                userLookupService,
                call
            )
            call.respondNewEmailSentPage(user.email!!)
        } else throw Exception("tokenResult was $tokenResult when trying to send a new reset password email")
    }

    private suspend fun resetPasswordPost(call: ApplicationCall) {
        val user = try {
            getUserFromCallParameters(
                call.request.queryParameters,
                userLookupService,
                resetPasswordExceptionUserVisibleMessage,
                "reset_password"
            )
        } catch (e: ApiError) {
            throw InvalidResetPassword()
        }

        val token = call.request.queryParameters["token"].orEmpty()
        if (Strings.isNullOrEmpty(token)) throw ResetPasswordException(
            "reset_password_no_token",
            "Token not present on resetting password"
        )

        val (message, newPassword) = passwordChecker.checkPasswordForErrors(call, user.email!!)

        if (message != null) return call.respondResetPasswordPage(message)
        logger.atInfo().addKeyValue("userCN", user.cn).addKeyValue("userGUID", user.getGUID())
            .log("Reset password post")
        when (val tokenResult = resetPasswordTokenService.consumeTokenIfValid(token, user.cn, user.getGUID())) {
            is PasswordTokenService.NoSuchToken -> {
                logger.error("Token did not exist on resetting password")
                throw InvalidResetPassword()
            }

            is PasswordTokenService.ExpiredToken -> {
                logger.atWarn().addKeyValue("userGUID", tokenResult.userGUID).log("Expired password reset token")
                val userEmail = userLookupService.lookupUserByGUID(user.getGUID()).email!!
                call.respondExpiredTokenPage(tokenResult, userEmail)
            }

            is PasswordTokenService.ValidToken -> {
                logger.atInfo().addKeyValue("userGUID", tokenResult.userGUID)
                    .log("Reset password form submitted with valid token")
                userService.resetPassword(tokenResult.userGUID, newPassword)
                logger.atInfo().addKeyValue("userGUID", tokenResult.userGUID).log("Password reset")
                userAuditService.resetPasswordAudit(user.cn, user.getGUID(), call)
                call.respondRedirect("/delta/reset-password/success")
            }
        }
    }


    private suspend fun ApplicationCall.respondNewEmailSentPage(userEmail: String) =
        respond(
            ThymeleafContent(
                "reset-password-email-sent",
                mapOf(
                    "deltaUrl" to deltaConfig.deltaWebsiteUrl,
                    "emailAddress" to userEmail,
                )
            )
        )

    private suspend fun ApplicationCall.respondSuccessPage() =
        respond(ThymeleafContent("reset-password-success", mapOf("deltaUrl" to deltaConfig.deltaWebsiteUrl)))

    private suspend fun ApplicationCall.respondResetPasswordPage(
        message: String? = null,
    ) {
        val mapOfValues = mutableMapOf(
            "deltaUrl" to deltaConfig.deltaWebsiteUrl,
        )
        if (message != null) mapOfValues += "message" to message
        respond(
            ThymeleafContent(
                "password-form",
                mapOfValues
            )
        )
    }

    private suspend fun ApplicationCall.respondExpiredTokenPage(
        tokenResult: PasswordTokenService.ExpiredToken,
        userEmail: String
    ) = respond(
        ThymeleafContent(
            "expired-reset-password",
            mapOf(
                "deltaUrl" to deltaConfig.deltaWebsiteUrl,
                "userEmail" to userEmail,
                "userGUID" to tokenResult.userGUID,
                "token" to tokenResult.token,
            )
        )
    )
}

const val resetPasswordExceptionUserVisibleMessage =
    "Something went wrong, please click the link in your latest password reset email or request a new one"

open class ResetPasswordException(
    errorCode: String,
    exceptionMessage: String,
    userVisibleMessage: String = resetPasswordExceptionUserVisibleMessage,
) : UserVisibleServerError(errorCode, exceptionMessage, userVisibleMessage, "Reset Password Error")

class InvalidResetPassword :
    ResetPasswordException(
        "reset_password_invalid",
        "Token and user combination did not exist on resetting password"
    )

fun getResetPasswordURL(token: String, userCN: String, authServiceUrl: String) =
    String.format(
        "%s/delta/reset-password?userCN=%s&token=%s",
        authServiceUrl,
        userCN.encodeURLParameter(),
        token.encodeURLParameter()
    )
