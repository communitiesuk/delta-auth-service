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

class DeltaSetPasswordController(
    private val deltaConfig: DeltaConfig,
    private val ldapConfig: LDAPConfig,
    private val emailConfig: EmailConfig,
    private val authServiceConfig: AuthServiceConfig,
    private val userService: UserService,
    private val setPasswordTokenService: SetPasswordTokenService,
    private val userLookupService: UserLookupService,
    private val emailService: EmailService,
) {
    private val logger = LoggerFactory.getLogger(this.javaClass)
    private val passwordChecker = PasswordChecker()

    fun setPasswordFormRoutes(route: Route) {
        route.post {
            setPasswordPost(call)
        }
        route.get {
            setPasswordGet(call)
        }
    }

    fun setPasswordSuccessRoute(route: Route) {
        route.get {
            call.respondSuccessPage()
        }
    }

    fun setPasswordExpired(route: Route) {
        route.post {
            setPasswordExpiredPost(call)
        }
    }

    private suspend fun setPasswordGet(call: ApplicationCall) {
        val userCN = call.request.queryParameters["userCN"].orEmpty()
        val token = call.request.queryParameters["token"].orEmpty()
        when (val tokenResult = setPasswordTokenService.validateToken(token, userCN)) {
            is SetPasswordTokenService.NoSuchToken -> {
                throw SetPasswordException("set_password_no_token", "Set password token did not exist")
            }

            is SetPasswordTokenService.ExpiredToken -> {
                call.respondExpiredTokenPage(tokenResult)
            }

            is SetPasswordTokenService.ValidToken -> {
                call.respondSetPasswordPage()
            }
        }
    }

    private suspend fun setPasswordExpiredPost(call: ApplicationCall) {
        val formParameters = call.receiveParameters()
        val userCN = formParameters["userCN"].orEmpty()
        val token = formParameters["token"].orEmpty()
        val tokenResult = setPasswordTokenService.consumeToken(token, userCN)
        if (tokenResult is SetPasswordTokenService.ExpiredToken) {
            sendNewSetPasswordLink(userCN)
            call.respondNewEmailSentPage(userCN.replace("!", "@"))
        } else throw Exception("tokenResult was $tokenResult when trying to send a new set password email")
    }

    private suspend fun setPasswordPost(call: ApplicationCall) {
        val formParameters = call.receiveParameters()
        val userCN = call.request.queryParameters["userCN"].orEmpty()
        val token = call.request.queryParameters["token"].orEmpty()
        val newPassword = formParameters["newPassword"].orEmpty()
        val confirmPassword = formParameters["confirmPassword"].orEmpty()

        if (Strings.isNullOrEmpty(userCN)) throw SetPasswordException(
            "set_password_no_user_cn",
            "User CN not present on setting password"
        )

        if (Strings.isNullOrEmpty(token)) throw SetPasswordException(
            "set_password_no_token",
            "Token not present on setting password"
        )


        val message: String? =
            if (Strings.isNullOrEmpty(newPassword)) "New password is required."
            else if (Strings.isNullOrEmpty(confirmPassword)) "Confirm password is required."
            else if (newPassword != confirmPassword) "Passwords did not match."
            else if (newPassword.length < 12) "Password must be at least 12 characters long."
            else if (passwordChecker.isCommonPassword(userCN, newPassword))
                "Passwords must not be a commonly used password format or contain your username"
            else null

        if (message != null) return call.respondSetPasswordPage(message)

        val tokenResult = setPasswordTokenService.consumeToken(token, userCN)
        call.respondToResult(tokenResult, newPassword)
    }

    private suspend fun sendNewSetPasswordLink(userCN: String) {
        val user = userLookupService.lookupUserByCn(userCN)
        emailService.sendTemplateEmail(
            "not-yet-enabled-user",
            EmailContacts(
                user.email!!,
                user.fullName,
                emailConfig.fromEmailAddress,
                emailConfig.fromEmailName,
                emailConfig.replyToEmailAddress,
                emailConfig.replyToEmailName,
            ),
            "DLUHC DELTA - Set Your Password",
            mapOf(
                "deltaUrl" to deltaConfig.deltaWebsiteUrl,
                "userFirstName" to user.firstName,
                "setPasswordUrl" to getSetPasswordURL(
                    setPasswordTokenService.createToken(userCN),
                    userCN,
                    authServiceConfig.serviceUrl
                )
            )
        )
    }

    class SetPasswordException(
        errorCode: String,
        exceptionMessage: String,
        userVisibleMessage: String = "Something went wrong, please click the link in your latest account activation email",
    ) : UserVisibleServerError(errorCode, exceptionMessage, userVisibleMessage, "Set Password Error")

    private suspend fun ApplicationCall.respondToResult(
        tokenResult: SetPasswordTokenService.TokenResult,
        newPassword: String
    ) {
        when (tokenResult) {
            is SetPasswordTokenService.NoSuchToken -> {
                throw SetPasswordException(
                    "set_password_invalid_token",
                    "Token did not exist on setting password"
                )
            }

            is SetPasswordTokenService.ExpiredToken -> {
                this.respondExpiredTokenPage(tokenResult)
            }

            is SetPasswordTokenService.ValidToken -> {
                val userDN = String.format(ldapConfig.deltaUserDnFormat, tokenResult.userCN)
                try {
                    userService.setPassword(userDN, newPassword)
                } catch (e: Exception) {
                    logger.atError().addKeyValue("UserDN", userDN).log("Error setting password for user with DN {}", e)
                    throw e
                }
                this.respondRedirect(authServiceConfig.serviceUrl + "/delta/set-password/success")
            }
        }
    }

    private suspend fun ApplicationCall.respondNewEmailSentPage(userEmail: String) =
        respond(
            ThymeleafContent(
                "registration-success",
                mapOf(
                    "deltaUrl" to deltaConfig.deltaWebsiteUrl,
                    "emailAddress" to userEmail,
                )
            )
        )

    private suspend fun ApplicationCall.respondSuccessPage() =
        respond(ThymeleafContent("set-password-success", mapOf("deltaUrl" to deltaConfig.deltaWebsiteUrl)))

    private suspend fun ApplicationCall.respondSetPasswordPage(
        message: String? = null,
    ) {
        val mapOfValues = mutableMapOf(
            "deltaUrl" to deltaConfig.deltaWebsiteUrl,
        )
        if (message != null) mapOfValues += "message" to message
        respond(
            ThymeleafContent(
                "set-password-form",
                mapOfValues
            )
        )
    }

    private suspend fun ApplicationCall.respondExpiredTokenPage(tokenResult: SetPasswordTokenService.ExpiredToken) =
        respond(
            ThymeleafContent(
                "expired-set-password",
                mapOf(
                    "deltaUrl" to deltaConfig.deltaWebsiteUrl,
                    "userEmail" to tokenResult.userCN.replace("!", "@"),
                    "userCN" to tokenResult.userCN,
                    "token" to tokenResult.token,
                )
            )
        )
}

fun getSetPasswordURL(token: String, userCN: String, authServiceUrl: String) =
    String.format(
        "%s/delta/set-password?userCN=%s&token=%s",
        authServiceUrl,
        userCN.encodeURLParameter(),
        token.encodeURLParameter()
    )