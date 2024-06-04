package uk.gov.communities.delta.auth.controllers.external

import com.google.common.base.Strings
import io.ktor.server.application.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import io.ktor.server.thymeleaf.*
import org.slf4j.LoggerFactory
import uk.gov.communities.delta.auth.config.AzureADSSOConfig
import uk.gov.communities.delta.auth.config.DeltaConfig
import uk.gov.communities.delta.auth.deltaWebsiteLoginRoute
import uk.gov.communities.delta.auth.plugins.NoUserException
import uk.gov.communities.delta.auth.services.*
import uk.gov.communities.delta.auth.utils.EmailAddressChecker

class DeltaForgotPasswordController(
    private val deltaConfig: DeltaConfig,
    private val ssoConfig: AzureADSSOConfig,
    private val resetPasswordTokenService: ResetPasswordTokenService,
    private val setPasswordTokenService: SetPasswordTokenService,
    private val userLookupService: UserLookupService,
    private val userGUIDMapService: UserGUIDMapService,
    private val emailService: EmailService,
) {
    private val logger = LoggerFactory.getLogger(this.javaClass)
    private val emailAddressChecker = EmailAddressChecker()

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
        else if (!emailAddressChecker.hasValidFormat(emailAddress)) "Must be a valid email address"
        else null
        if (message != null) return call.respondForgotPasswordPage(message, emailAddress)
        logger.atInfo().addKeyValue("emailAddress", emailAddress).log("Forgot password request")

        val ssoClientMatchingEmailDomain = ssoConfig.ssoClients.firstOrNull {
            it.required && emailAddress.lowercase().endsWith(it.emailDomain)
        }
        if (ssoClientMatchingEmailDomain != null) {
            logger.atInfo().addKeyValue("ssoClient", ssoClientMatchingEmailDomain.internalId)
                .log("Forgot password email matches required SSO domain, redirecting")
            return call.respondRedirect(
                deltaWebsiteLoginRoute(
                    deltaConfig.deltaWebsiteUrl,
                    ssoClientMatchingEmailDomain.internalId,
                    emailAddress,
                    "sso_forgot_password",
                )
            )
        }

        try {
            val userGUID = userGUIDMapService.getGUIDFromEmail(emailAddress)
            val user = userLookupService.lookupUserByGUID(userGUID)
            if (!user.accountEnabled && setPasswordTokenService.passwordNeverSetForUserCN(user.getGUID()))
                emailService.sendPasswordNeverSetEmail(user, setPasswordTokenService.createToken(user.getGUID()), call)
            else emailService.sendResetPasswordEmail(
                user,
                resetPasswordTokenService.createToken(user.getGUID()),
                null,
                call
            )
        } catch (e: NoUserException) {
            emailService.sendNoUserEmail(emailAddress)
        } catch (e: Exception) {
            logger.atError().addKeyValue("emailAddress", emailAddress)
                .log("Unexpected error occurred when sending a forgot password link")
            throw e
        }
        call.redirectSentEmailPage(emailAddress)
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
