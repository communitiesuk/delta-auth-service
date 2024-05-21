package uk.gov.communities.delta.auth.controllers.internal

import io.ktor.http.*
import io.ktor.server.application.*
import io.ktor.server.auth.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import org.slf4j.LoggerFactory
import uk.gov.communities.delta.auth.config.AzureADSSOConfig
import uk.gov.communities.delta.auth.plugins.ApiError
import uk.gov.communities.delta.auth.repositories.LdapUser
import uk.gov.communities.delta.auth.services.*

class AdminEmailController(
    private val ssoConfig: AzureADSSOConfig,
    private val emailService: EmailService,
    private val userLookupService: UserLookupService,
    private val setPasswordTokenService: SetPasswordTokenService,
    private val resetPasswordTokenService: ResetPasswordTokenService,
) : AdminUserController(userLookupService) {

    private val logger = LoggerFactory.getLogger(javaClass)

    // Help desk are read-only-admin s and can trigger these emails as well as other admins
    private val rolesThatCanSendPasswordEmails =
        arrayOf(DeltaSystemRole.ADMIN, DeltaSystemRole.READ_ONLY_ADMIN)

    fun route(route: Route) {
        route.post("/activation") { adminSendActivationEmail(call) }
        route.post("/reset-password") { adminSendResetPasswordEmail(call) }
    }

    private suspend fun adminSendActivationEmail(call: ApplicationCall) {
        val receivingUser = getReceivingUserFromCall(call)

        checkUserHasPermittedRole(rolesThatCanSendPasswordEmails, call)

        if (receivingUser.accountEnabled) {
            logger.atError().addKeyValue("userCNToSendEmailTo", receivingUser.cn)
                .log("User already enabled on activation email request")
            throw ApiError(
                HttpStatusCode.BadRequest,
                "already_enabled",
                "User already enabled on activation email request",
                "User already enabled"
            )
        }

        if (isRequiredSSOUser(receivingUser)) {
            logger.atError().addKeyValue("userCNToSendEmailTo", receivingUser.cn)
                .log("Trying to send activation email to SSO User")
            throw ApiError(
                HttpStatusCode.BadRequest,
                "no_emails_to_sso_users",
                "Trying to send activation email to SSO User",
                "SSO user - account is automatically activated, can be enabled using the Enable Access button"
            )
        }

        try {
            val token = setPasswordTokenService.createToken(receivingUser.cn, receivingUser.getGUID())
            emailService.sendSetPasswordEmail(
                receivingUser,
                token,
                call.principal<OAuthSession>()!!,
                userLookupService,
                call
            )
        } catch (e: Exception) {
            logger.atError().addKeyValue("userCNToSendEmailTo", receivingUser.cn).log("Failed to send activation email")
            throw ApiError(
                HttpStatusCode.InternalServerError,
                "email_failure",
                "Failed to send activation email",
                "Failed to send activation email"
            )
        }
        logger.atInfo().addKeyValue("userCNToSendEmailTo", receivingUser.cn).log("New activation email sent")
        return call.respond(mapOf("message" to "New activation email sent successfully"))
    }

    private suspend fun adminSendResetPasswordEmail(call: ApplicationCall) {
        val receivingUser = getReceivingUserFromCall(call)

        checkUserHasPermittedRole(rolesThatCanSendPasswordEmails, call)

        if (!receivingUser.accountEnabled) {
            logger.atWarn().addKeyValue("userCNToSendEmailTo", receivingUser.cn).log("User not enabled")
            throw ApiError(
                HttpStatusCode.BadRequest,
                "not_enabled",
                "User not enabled on reset password email request",
                "User must be enabled to send password reset email",
            )
        }

        if (isRequiredSSOUser(receivingUser)) {
            logger.atWarn().addKeyValue("userCNToSendEmailTo", receivingUser.cn)
                .log("Trying to send reset password to SSO User")
            throw ApiError(
                HttpStatusCode.BadRequest,
                "no_emails_to_sso_users",
                "Trying to send reset password email to SSO User",
                "SSO user - account doesn't have a password"
            )
        }

        try {
            val token = resetPasswordTokenService.createToken(receivingUser.cn, receivingUser.getGUID())
            emailService.sendResetPasswordEmail(
                receivingUser,
                token,
                call.principal<OAuthSession>()!!,
                userLookupService,
                call
            )
        } catch (e: Exception) {
            logger.atError().addKeyValue("userCNToSendEmailTo", receivingUser.cn).log("Failed to send email")
            throw ApiError(
                HttpStatusCode.InternalServerError,
                "email_failure",
                "Failed to send reset password email",
                "Failed to send reset password email"
            )
        }
        logger.atInfo().addKeyValue("userCNToSendEmailTo", receivingUser.cn).log("Reset password email sent")
        return call.respond(mapOf("message" to "Reset password email sent successfully"))
    }

    private suspend fun getReceivingUserFromCall(call: ApplicationCall): LdapUser {
        val receivingEmailAddress = call.parameters["userEmail"]!! // TODO DT-1022 - Use userGUID once receiving
        val receivingUser = userLookupService.lookupUserByEmail(receivingEmailAddress)
        return receivingUser
    }

    private fun isRequiredSSOUser(receivingUser: LdapUser): Boolean {
        return ssoConfig.ssoClients.any {
            it.required && receivingUser.email!!.lowercase().endsWith(it.emailDomain)
        }
    }
}
