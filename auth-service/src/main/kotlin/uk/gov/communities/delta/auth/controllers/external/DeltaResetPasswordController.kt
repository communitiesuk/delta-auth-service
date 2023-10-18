package uk.gov.communities.delta.auth.controllers.external

import com.google.common.base.Strings
import io.ktor.http.*
import io.ktor.server.application.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import io.ktor.server.thymeleaf.*
import org.slf4j.LoggerFactory
import uk.gov.communities.delta.auth.config.AuthServiceConfig
import uk.gov.communities.delta.auth.config.DeltaConfig
import uk.gov.communities.delta.auth.config.EmailConfig
import uk.gov.communities.delta.auth.config.LDAPConfig
import uk.gov.communities.delta.auth.plugins.UserVisibleServerError
import uk.gov.communities.delta.auth.services.*
import uk.gov.communities.delta.auth.utils.PasswordChecker

class DeltaResetPasswordController(
    private val deltaConfig: DeltaConfig,
    private val ldapConfig: LDAPConfig,
    private val emailConfig: EmailConfig,
    private val authServiceConfig: AuthServiceConfig,
    private val userService: UserService,
    private val resetPasswordTokenService: ResetPasswordTokenService,
    private val userLookupService: UserLookupService,
    private val emailService: EmailService,
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
        val userCN = call.request.queryParameters["userCN"].orEmpty()
        val token = call.request.queryParameters["token"].orEmpty()
        when (val tokenResult = resetPasswordTokenService.validateToken(token, userCN)) {
            is PasswordTokenService.NoSuchToken -> {
                logger.error("Reset password get request with invalid token and/or userCN")
                throw ResetPasswordException("reset_password_no_token", "Reset password token did not exist")
            }

            is PasswordTokenService.ExpiredToken -> {
                logger.atWarn().addKeyValue("userCN", userCN).log("Reset password get request with expired token")
                call.respondExpiredTokenPage(tokenResult)
            }

            is PasswordTokenService.ValidToken -> {
                logger.atInfo().addKeyValue("userCN", userCN).log("Reset password get request with valid token")
                call.respondResetPasswordPage()
            }
        }
    }

    private suspend fun resetPasswordExpiredPost(call: ApplicationCall) {
        val formParameters = call.receiveParameters()
        val userCN = formParameters["userCN"].orEmpty()
        val token = formParameters["token"].orEmpty()
        val tokenResult = resetPasswordTokenService.consumeToken(token, userCN)
        if (tokenResult is PasswordTokenService.ExpiredToken) {
            logger.atInfo().addKeyValue("userCN", userCN).log("Sending new reset password link (after expiry)")
            sendNewResetPasswordLink(userCN)
            call.respondNewEmailSentPage(userCN.replace("!", "@"))
        } else throw Exception("tokenResult was $tokenResult when trying to send a new reset password email")
    }

    private suspend fun resetPasswordPost(call: ApplicationCall) {
        val userCN = call.request.queryParameters["userCN"].orEmpty()
        val token = call.request.queryParameters["token"].orEmpty()

        if (Strings.isNullOrEmpty(userCN)) throw ResetPasswordException(
            "reset_password_no_user_cn",
            "User CN not present on resetting password"
        )

        if (Strings.isNullOrEmpty(token)) throw ResetPasswordException(
            "reset_password_no_token",
            "Token not present on resetting password"
        )

        val (message, newPassword) = passwordChecker.checkPasswordForErrors(call, userCN)

        if (message != null) return call.respondResetPasswordPage(message)
        logger.atInfo().addKeyValue("userCN", userCN).log("Reset password post")

        when (val tokenResult = resetPasswordTokenService.consumeToken(token, userCN)) {
            is PasswordTokenService.NoSuchToken -> {
                logger.error("Token did not exist on resetting password")
                throw ResetPasswordException(
                    "reset_password_invalid_token",
                    "Token did not exist on resetting password"
                )
            }

            is PasswordTokenService.ExpiredToken -> {
                logger.atWarn().addKeyValue("userCN", tokenResult.userCN).log("Expired password reset token")
                call.respondExpiredTokenPage(tokenResult)
            }

            is PasswordTokenService.ValidToken -> {
                logger.atInfo().addKeyValue("userCN", tokenResult.userCN)
                    .log("Reset password form submitted with valid token")
                val userDN = String.format(ldapConfig.deltaUserDnFormat, tokenResult.userCN)
                try {
                    userService.resetPassword(userDN, newPassword)
                    logger.atInfo().addKeyValue("userCN", tokenResult.userCN).log("Password reset")
                } catch (e: Exception) {
                    logger.atError().addKeyValue("UserDN", userDN).addKeyValue("userCN", tokenResult.userCN)
                        .log("Error resetting password for user", e)
                    throw e
                }
                call.respondRedirect("/delta/reset-password/success")
            }
        }
    }

    private suspend fun sendNewResetPasswordLink(userCN: String) {
        val user = userLookupService.lookupUserByCn(userCN)
        logger.atInfo().addKeyValue("userCN", userCN).addKeyValue("emailAddress", user.email)
            .log("Sending reset password link")
        val token = resetPasswordTokenService.createToken(userCN)
        emailService.sendTemplateEmail(
            "reset-password",
            EmailContacts(
                user.email!!,
                user.fullName,
                emailConfig.fromEmailAddress,
                emailConfig.fromEmailName,
                emailConfig.replyToEmailAddress,
                emailConfig.replyToEmailName,
            ),
            "DLUHC DELTA - Reset Your Password",
            mapOf(
                "deltaUrl" to deltaConfig.deltaWebsiteUrl,
                "userFirstName" to user.firstName,
                "resetPasswordUrl" to getResetPasswordURL(
                    token,
                    userCN,
                    authServiceConfig.serviceUrl
                )
            )
        )
        logger.atInfo().addKeyValue("userCN", userCN).addKeyValue("emailAddress", user.email)
            .log("Sent reset password link")
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

    private suspend fun ApplicationCall.respondExpiredTokenPage(tokenResult: PasswordTokenService.ExpiredToken) =
        respond(
            ThymeleafContent(
                "expired-reset-password",
                mapOf(
                    "deltaUrl" to deltaConfig.deltaWebsiteUrl,
                    "userEmail" to tokenResult.userCN.replace("!", "@"),
                    "userCN" to tokenResult.userCN,
                    "token" to tokenResult.token,
                )
            )
        )
}

class ResetPasswordException(
    errorCode: String,
    exceptionMessage: String,
    userVisibleMessage: String = "Something went wrong, please click the link in your latest password reset email or request a new one.",
) : UserVisibleServerError(errorCode, exceptionMessage, userVisibleMessage, "Reset Password Error")

fun getResetPasswordURL(token: String, userCN: String, authServiceUrl: String) =
    String.format(
        "%s/delta/reset-password?userCN=%s&token=%s",
        authServiceUrl,
        userCN.encodeURLParameter(),
        token.encodeURLParameter()
    )