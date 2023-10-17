package uk.gov.communities.delta.auth.controllers.external

import com.google.common.base.Strings
import io.ktor.server.application.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import io.ktor.server.thymeleaf.*
import org.slf4j.LoggerFactory
import uk.gov.communities.delta.auth.config.*
import uk.gov.communities.delta.auth.deltaRouteWithEmail
import uk.gov.communities.delta.auth.services.*
import javax.naming.NameNotFoundException

class DeltaForgotPasswordController(
    private val deltaConfig: DeltaConfig,
    private val emailConfig: EmailConfig,
    private val authServiceConfig: AuthServiceConfig,
    private val ssoConfig: AzureADSSOConfig,
    private val resetPasswordTokenService: ResetPasswordTokenService,
    private val registrationSetPasswordTokenService: RegistrationSetPasswordTokenService,
    private val userLookupService: UserLookupService,
    private val emailService: EmailService,
) {
    private val logger = LoggerFactory.getLogger(this.javaClass)

    fun forgotPasswordFormRoutes(route: Route) {
        route.post {
            forgotPasswordPost(call)
        }
        route.get {
            call.respondForgotPasswordPage()
        }
    }

    fun forgotPasswordEmailSentRoute(route: Route) {
        route.get {
            val emailAddress = call.request.queryParameters["emailAddress"]!!
            call.respondEmailSentPage(emailAddress)
        }
    }

    private suspend fun forgotPasswordPost(call: ApplicationCall) {
        val formParameters = call.receiveParameters()
        val emailAddress = formParameters["emailAddress"].orEmpty()

        val message = if (Strings.isNullOrEmpty(emailAddress)) "An email address is required."
        else if (!LDAPConfig.VALID_EMAIL_REGEX.matches(emailAddress)) "Must be a valid email address"
        else null
        if (message != null) return call.respondForgotPasswordPage(message, emailAddress)
        logger.atInfo().addKeyValue("emailAddress", emailAddress).log("Forgot password request")

        val ssoClientMatchingEmailDomain = ssoConfig.ssoClients.firstOrNull {
            it.required && emailAddress.lowercase().endsWith(it.emailDomain)
        }
        if (ssoClientMatchingEmailDomain != null)
            return call.respondRedirect(
                deltaRouteWithEmail(
                    deltaConfig.deltaWebsiteUrl,
                    ssoClientMatchingEmailDomain.internalId,
                    emailAddress
                )
            )

        val userCN = emailAddress.replace("@", "!")
        try {
            val user = userLookupService.lookupUserByCn(userCN)
            if (!user.accountEnabled && registrationSetPasswordTokenService.passwordNeverSetForUserCN(userCN))
                sendSetPasswordLink(user.email!!, userCN, user.firstName, user.fullName)
            else sendForgotPasswordLink(user)
        } catch (e: NameNotFoundException) {
            sendNoUserEmail(emailAddress)
        } catch (e: Exception) {
            logger.atError().addKeyValue("emailAddress", emailAddress)
                .log("Unexpected error occurred when sending a forgot password link")
            throw e
        }
        call.redirectSentEmailPage(emailAddress)
    }

    private suspend fun sendForgotPasswordLink(user: LdapUser) {
        logger.atInfo().addKeyValue("emailAddress", user.email).log("Sending reset-password email")
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
                    resetPasswordTokenService.createToken(user.cn),
                    user.cn,
                    authServiceConfig.serviceUrl
                )
            )
        )
    }

    private fun sendNoUserEmail(emailAddress: String) {
        logger.atInfo().addKeyValue("emailAddress", emailAddress).log("Sending no-user-account email")
        emailService.sendTemplateEmail(
            "no-user-account",
            EmailContacts(
                emailAddress,
                emailAddress,
                emailConfig.fromEmailAddress,
                emailConfig.fromEmailName,
                emailConfig.replyToEmailAddress,
                emailConfig.replyToEmailName,
            ),
            "DLUHC DELTA - No User Account",
            mapOf("deltaUrl" to deltaConfig.deltaWebsiteUrl)
        )
        logger.atInfo().addKeyValue("emailAddress", emailAddress).log("Sent no-user-account email")
    }

    private suspend fun sendSetPasswordLink(
        emailAddress: String,
        userCN: String,
        userFirstName: String,
        userFullName: String
    ) {
        logger.atInfo().addKeyValue("emailAddress", emailAddress).log("Sending password-never-set email")
        emailService.sendTemplateEmail(
            "password-never-set",
            EmailContacts(
                emailAddress,
                userFullName,
                emailConfig.fromEmailAddress,
                emailConfig.fromEmailName,
                emailConfig.replyToEmailAddress,
                emailConfig.replyToEmailName,
            ),
            "DLUHC DELTA - Set Password",
            mapOf(
                "deltaUrl" to deltaConfig.deltaWebsiteUrl,
                "setPasswordUrl" to getSetPasswordURL(
                    registrationSetPasswordTokenService.createToken(userCN),
                    userCN,
                    authServiceConfig.serviceUrl
                ),
                "userFirstName" to userFirstName,
            )
        )
        logger.atInfo().addKeyValue("emailAddress", emailAddress).log("Sent password-never-set email")
    }

    private suspend fun ApplicationCall.redirectSentEmailPage(emailAddress: String) =
        respondRedirect("/delta/forgot-password/email-sent?emailAddress=$emailAddress")

    private suspend fun ApplicationCall.respondEmailSentPage(emailAddress: String) =
        respond(
            ThymeleafContent(
                "reset-password-email-sent",
                mapOf(
                    "deltaUrl" to deltaConfig.deltaWebsiteUrl,
                    "emailAddress" to emailAddress
                )
            )
        )

    private suspend fun ApplicationCall.respondForgotPasswordPage(
        message: String? = null,
        emailAddress: String? = null,
    ) {
        val mapOfValues = mutableMapOf(
            "deltaUrl" to deltaConfig.deltaWebsiteUrl,
        )
        if (message != null) mapOfValues += "message" to message
        if (emailAddress != null) mapOfValues += "emailAddress" to emailAddress
        respond(
            ThymeleafContent(
                "forgot-password",
                mapOfValues
            )
        )
    }
}