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
import uk.gov.communities.delta.auth.plugins.ApiError
import uk.gov.communities.delta.auth.plugins.UserVisibleServerError
import uk.gov.communities.delta.auth.services.*
import uk.gov.communities.delta.auth.utils.PasswordChecker
import uk.gov.communities.delta.auth.utils.getUserFromCallParameters
import java.util.*

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
        val user = try {
            getUserFromCallParameters(  // TODO DT-976-2 - just get GUID once CN not needed
                call.request.queryParameters,
                userLookupService,
                setPasswordExceptionUserVisibleMessage,
                "set_password_get"
            )
        } catch (e: ApiError) {
            throw InvalidSetPassword()
        }
        val token = call.request.queryParameters["token"].orEmpty()
        // TODO DT-976-2 - validate tokens using GUID not CN
        when (val tokenResult = setPasswordTokenService.validateToken(token, user.cn, user.getGUID())) {
            is PasswordTokenService.NoSuchToken -> {
                throw InvalidSetPassword()
            }

            is PasswordTokenService.ExpiredToken -> {
                val userEmail = userLookupService.lookupUserByGUID(user.getGUID()).email!!
                call.respondExpiredTokenPage(tokenResult, userEmail)
            }

            is PasswordTokenService.ValidToken -> {
                call.respondSetPasswordPage()
            }
        }
    }

    private suspend fun setPasswordExpiredPost(call: ApplicationCall) {
        val formParameters = call.receiveParameters()
        val userGUID = UUID.fromString(formParameters["userGUID"]!!)
        val user = userLookupService.lookupUserByGUID(userGUID)
        val token = formParameters["token"].orEmpty()
        val tokenResult = setPasswordTokenService.consumeTokenIfValid(token, user.cn, userGUID)
        if (tokenResult is PasswordTokenService.ExpiredToken) {
            emailService.sendNotYetEnabledEmail(
                userLookupService.lookupUserByGUID(userGUID),
                setPasswordTokenService.createToken(user.cn, userGUID),
                call
            )
            call.respondNewEmailSentPage(user.email!!)
        } else throw Exception("tokenResult was $tokenResult when trying to send a new set password email")
    }

    private suspend fun setPasswordPost(call: ApplicationCall) {
        val user = try {
            getUserFromCallParameters(
                call.request.queryParameters,
                userLookupService,
                setPasswordExceptionUserVisibleMessage,
                "set_password"
            )
        } catch (e: ApiError) {
            throw InvalidSetPassword()
        }

        val token = call.request.queryParameters["token"].orEmpty()
        if (Strings.isNullOrEmpty(token)) throw SetPasswordException(
            "set_password_no_token",
            "Token not present on setting password"
        )

        val (message, newPassword) = passwordChecker.checkPasswordForErrors(call, user.email!!)
        if (message != null) return call.respondSetPasswordPage(message)

        when (val tokenResult = setPasswordTokenService.consumeTokenIfValid(token, user.cn, user.getGUID())) {
            is PasswordTokenService.NoSuchToken -> {
                InvalidSetPassword()
            }

            is PasswordTokenService.ExpiredToken -> {
                val userEmail = user.email
                call.respondExpiredTokenPage(tokenResult, userEmail)
            }

            is PasswordTokenService.ValidToken -> {
                try {
                    userService.setPasswordAndEnable(user.dn, newPassword)
                } catch (e: Exception) {
                    logger.atError().addKeyValue("UserDN", user.dn).log("Error setting password for user", e)
                    throw e
                }
                userAuditService.setPasswordAudit(user.cn, user.getGUID(), call)
                call.respondRedirect("/delta/set-password/success")
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
            "expired-set-password",
            mapOf(
                "deltaUrl" to deltaConfig.deltaWebsiteUrl,
                "userEmail" to userEmail,
                "userGUID" to tokenResult.userGUID,
                "token" to tokenResult.token,
            )
        )
    )
}

const val setPasswordExceptionUserVisibleMessage =
    "Something went wrong, please click the link in your latest account activation email"

open class SetPasswordException(
    errorCode: String,
    exceptionMessage: String,
    userVisibleMessage: String = setPasswordExceptionUserVisibleMessage,
) : UserVisibleServerError(errorCode, exceptionMessage, userVisibleMessage, "Set Password Error")

class InvalidSetPassword :
    SetPasswordException(
        "set_password_invalid",
        "Token and user combination did not exist on setting password"
    )

fun getSetPasswordURL(token: String, userCN: String, authServiceUrl: String) =
    String.format(
        "%s/delta/set-password?userCN=%s&token=%s",
        authServiceUrl,
        userCN.encodeURLParameter(),
        token.encodeURLParameter()
    )
