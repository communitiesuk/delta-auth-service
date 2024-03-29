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
import uk.gov.communities.delta.auth.config.LDAPConfig
import uk.gov.communities.delta.auth.plugins.UserVisibleServerError
import uk.gov.communities.delta.auth.services.*
import uk.gov.communities.delta.auth.utils.PasswordChecker

class DeltaSetPasswordController(
    private val deltaConfig: DeltaConfig,
    private val ldapConfig: LDAPConfig,
    private val userService: UserService,
    private val setPasswordTokenService: SetPasswordTokenService,
    private val userLookupService: UserLookupService,
    private val emailService: EmailService,
    private val userAuditService: UserAuditService,
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
            is PasswordTokenService.NoSuchToken -> {
                throw SetPasswordException("set_password_no_token", "Set password token did not exist")
            }

            is PasswordTokenService.ExpiredToken -> {
                call.respondExpiredTokenPage(tokenResult)
            }

            is PasswordTokenService.ValidToken -> {
                call.respondSetPasswordPage()
            }
        }
    }

    private suspend fun setPasswordExpiredPost(call: ApplicationCall) {
        val formParameters = call.receiveParameters()
        val userCN = formParameters["userCN"].orEmpty()
        val token = formParameters["token"].orEmpty()
        val tokenResult = setPasswordTokenService.consumeTokenIfValid(token, userCN)
        if (tokenResult is PasswordTokenService.ExpiredToken) {
            emailService.sendNotYetEnabledEmail(
                userLookupService.lookupUserByCn(userCN),
                setPasswordTokenService.createToken(userCN),
                call
            )
            call.respondNewEmailSentPage(userCN.replace("!", "@"))
        } else throw Exception("tokenResult was $tokenResult when trying to send a new set password email")
    }

    private suspend fun setPasswordPost(call: ApplicationCall) {
        val userCN = call.request.queryParameters["userCN"].orEmpty()
        val token = call.request.queryParameters["token"].orEmpty()

        if (Strings.isNullOrEmpty(userCN)) throw SetPasswordException(
            "set_password_no_user_cn",
            "User CN not present on setting password"
        )

        if (Strings.isNullOrEmpty(token)) throw SetPasswordException(
            "set_password_no_token",
            "Token not present on setting password"
        )

        val (message, newPassword) = passwordChecker.checkPasswordForErrors(call, userCN)
        if (message != null) return call.respondSetPasswordPage(message)

        when (val tokenResult = setPasswordTokenService.consumeTokenIfValid(token, userCN)) {
            is PasswordTokenService.NoSuchToken -> {
                throw SetPasswordException(
                    "set_password_invalid_token",
                    "Token did not exist on setting password"
                )
            }

            is PasswordTokenService.ExpiredToken -> {
                call.respondExpiredTokenPage(tokenResult)
            }

            is PasswordTokenService.ValidToken -> {
                val userDN = String.format(ldapConfig.deltaUserDnFormat, tokenResult.userCN)
                try {
                    userService.setPasswordAndEnable(userDN, newPassword)
                } catch (e: Exception) {
                    logger.atError().addKeyValue("UserDN", userDN).log("Error setting password for user", e)
                    throw e
                }
                userAuditService.setPasswordAudit(userCN, call)
                call.respondRedirect("/delta/set-password/success")
            }
        }
    }

    class SetPasswordException(
        errorCode: String,
        exceptionMessage: String,
        userVisibleMessage: String = "Something went wrong, please click the link in your latest account activation email",
    ) : UserVisibleServerError(errorCode, exceptionMessage, userVisibleMessage, "Set Password Error")

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
                "password-form",
                mapOfValues
            )
        )
    }

    private suspend fun ApplicationCall.respondExpiredTokenPage(tokenResult: PasswordTokenService.ExpiredToken) =
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
