package uk.gov.communities.delta.auth.controllers.internal

import io.ktor.http.*
import io.ktor.server.application.*
import io.ktor.server.auth.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import org.slf4j.LoggerFactory
import uk.gov.communities.delta.auth.config.AzureADSSOConfig
import uk.gov.communities.delta.auth.config.LDAPConfig
import uk.gov.communities.delta.auth.repositories.LdapUser
import uk.gov.communities.delta.auth.services.*

class AdminEmailController(
    private val ssoConfig: AzureADSSOConfig,
    private val emailService: EmailService,
    private val userLookupService: UserLookupService,
    private val setPasswordTokenService: SetPasswordTokenService,
    private val resetPasswordTokenService: ResetPasswordTokenService,
) {
    private val logger = LoggerFactory.getLogger(javaClass)

    fun route(route: Route) {
        route.post("/activation") { adminSendActivationEmail(call) }
        route.post("/reset-password") { adminSendResetPasswordEmail(call) }
    }

    private suspend fun adminSendActivationEmail(call: ApplicationCall) {
        val (callingUser, receivingUser) = getUsersFromCall(call)

        if (!userHasPermissionToTriggerEmails(callingUser)) return call.respondUnauthorised(receivingUser)

        if (receivingUser.accountEnabled) {
            logger.atError().addKeyValue("userCNToSendEmailTo", receivingUser.cn).log("User already enabled")
            return call.respondText("User is already enabled", status = HttpStatusCode.ExpectationFailed)
        }

        if (isRequiredSSOUser(receivingUser)) {
            logger.atError().addKeyValue("userCNToSendEmailTo", receivingUser.cn)
                .log("Trying to send activation email to SSO User")
            return call.respondText(
                "SSO user - account is automatically activated, can be enabled using the Enable Access button",
                status = HttpStatusCode.ExpectationFailed
            )
        }

        try {
            val token = setPasswordTokenService.createToken(receivingUser.cn)
            emailService.sendSetPasswordEmail(receivingUser, token, call)
        } catch (e: Exception) {
            logger.atError().addKeyValue("userCNToSendEmailTo", receivingUser.cn).log("Failed to send email")
            return call.respondText("Failed to send email", status = HttpStatusCode.ExpectationFailed)
        }
        logger.atInfo().addKeyValue("userCNToSendEmailTo", receivingUser.cn).log("New activation email sent")
        return call.respondText("New activation email sent")
    }

    private suspend fun adminSendResetPasswordEmail(call: ApplicationCall) {
        val (callingUser, receivingUser) = getUsersFromCall(call)

        if (!userHasPermissionToTriggerEmails(callingUser)) return call.respondUnauthorised(receivingUser)

        if (!receivingUser.accountEnabled) {
            logger.atError().addKeyValue("userCNToSendEmailTo", receivingUser.cn).log("User not enabled")
            return call.respondText("User not enabled", status = HttpStatusCode.ExpectationFailed)
        }

        if (isRequiredSSOUser(receivingUser)) {
            logger.atError().addKeyValue("userCNToSendEmailTo", receivingUser.cn)
                .log("Trying to send reset password to SSO User")
            return call.respondText(
                "SSO user - account doesn't have a password",
                status = HttpStatusCode.ExpectationFailed
            )
        }

        try {
            val token = resetPasswordTokenService.createToken(receivingUser.cn)
            emailService.sendResetPasswordEmail(receivingUser, token, call)
        } catch (e: Exception) {
            logger.atError().addKeyValue("userCNToSendEmailTo", receivingUser.cn).log("Failed to send email")
            return call.respondText("Failed to send email", status = HttpStatusCode.ExpectationFailed)
        }
        logger.atInfo().addKeyValue("userCNToSendEmailTo", receivingUser.cn).log("Reset password email sent")
        return call.respondText("Reset password email sent")
    }

    private suspend fun getUsersFromCall(call: ApplicationCall): Array<LdapUser> {
        val session = call.principal<OAuthSession>()!!
        val callingUser = userLookupService.lookupUserByCn(session.userCn)
        val receivingEmailAddress = call.parameters["userEmail"]!!
        val receivingUserCN = LDAPConfig.emailToCN(receivingEmailAddress)
        val receivingUser = userLookupService.lookupUserByCn(receivingUserCN)
        return arrayOf(callingUser, receivingUser)
    }

    // Help desk are read-only-admin s and can trigger these emails as well as other admins
    private val triggerEmailsAdminGroupCNs =
        listOf("admin", "read-only-admin").map { LDAPConfig.DATAMART_DELTA_PREFIX + it }

    private fun userHasPermissionToTriggerEmails(callingUser: LdapUser): Boolean {
        return callingUser.memberOfCNs.any { triggerEmailsAdminGroupCNs.contains(it) }
    }

    private fun isRequiredSSOUser(receivingUser: LdapUser): Boolean {
        return ssoConfig.ssoClients.any {
            it.required && receivingUser.email!!.lowercase().endsWith(it.emailDomain)
        }
    }

    private suspend fun ApplicationCall.respondUnauthorised(receivingUser: LdapUser) {
        logger.atWarn().withSession(this.principal<OAuthSession>()!!)
            .addKeyValue("userCNToSendEmailTo", receivingUser.cn)
            .log("User does not have permission to trigger password emails for {}", receivingUser.cn)
        respond(
            HttpStatusCode.Forbidden,
            mapOf(
                "error" to "forbidden",
                "error_description" to "User does not have permission to trigger password emails for '$receivingUser.cn'"
            )
        )
    }
}