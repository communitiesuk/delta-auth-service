package uk.gov.communities.delta.auth.services

import io.ktor.server.application.*
import jakarta.mail.Address
import jakarta.mail.internet.InternetAddress
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.slf4j.LoggerFactory
import uk.gov.communities.delta.auth.config.AuthServiceConfig
import uk.gov.communities.delta.auth.config.DeltaConfig
import uk.gov.communities.delta.auth.config.EmailConfig
import uk.gov.communities.delta.auth.controllers.external.getResetPasswordURL
import uk.gov.communities.delta.auth.controllers.external.getSetPasswordURL
import uk.gov.communities.delta.auth.repositories.EmailRepository
import uk.gov.communities.delta.auth.repositories.LdapUser
import uk.gov.communities.delta.auth.utils.timed
import java.util.*

class EmailService(
    private val emailConfig: EmailConfig,
    private val deltaConfig: DeltaConfig,
    private val authServiceConfig: AuthServiceConfig,
    private val userAuditService: UserAuditService,
    private val emailRepository: EmailRepository,
) {
    private val logger = LoggerFactory.getLogger(javaClass)

    private suspend fun sendTemplateEmail(
        template: String,
        emailContacts: EmailContacts,
        subject: String,
        mappedValues: Map<String, String>,
    ) {
        withContext(Dispatchers.IO) {
            logger.timed(
                "Send templated email",
                { listOf(Pair("emailTemplate", template)) }
            ) {
                emailRepository.sendEmail(template, emailContacts, subject, mappedValues)
            }
        }
    }

    suspend fun sendAlreadyAUserEmail(
        firstName: String,
        userCN: String,
        contacts: EmailContacts,
    ) {
        sendTemplateEmail(
            "already-a-user",
            contacts,
            "DLUHC Delta - Existing Account",
            mapOf(
                "deltaUrl" to deltaConfig.deltaWebsiteUrl,
                "userFirstName" to firstName,
            )
        )
        logger.atInfo().addKeyValue("userCN", userCN).log("Sent already-a-user email")
    }

    suspend fun sendSetPasswordEmail(
        user: LdapUser,
        token: String,
        triggeringAdminSession: OAuthSession?,
        userLookupService: UserLookupService, // TODO DT-976-2 - remove once GUID is definitely in session
        call: ApplicationCall
    ) {
        sendSetPasswordEmail(
            user.firstName,
            token,
            user.cn,
            user.getGUID(),
            triggeringAdminSession,
            userLookupService,
            EmailContacts(user.email!!, user.fullName, emailConfig),
            call
        )
    }

    suspend fun sendSetPasswordEmail(
        firstName: String,
        token: String,
        userCN: String,
        userGUID: UUID,
        triggeringAdminSession: OAuthSession?,
        userLookupService: UserLookupService, // TODO DT-976-2 - remove once GUID is definitely in session
        contacts: EmailContacts,
        call: ApplicationCall,
    ) {
        sendTemplateEmail(
            "new-user",
            contacts,
            "DLUHC Delta - New User Account",
            mapOf(
                "deltaUrl" to deltaConfig.deltaWebsiteUrl,
                "userFirstName" to firstName,
                "setPasswordUrl" to getSetPasswordURL(
                    token,
                    userCN,
                    authServiceConfig.serviceUrl
                )
            )
        )
        if (triggeringAdminSession != null) userAuditService.adminSetPasswordEmailAudit(
            userCN,
            userGUID,
            triggeringAdminSession.userCn,
            triggeringAdminSession.getUserGUID(userLookupService),
            call
        )
        else userAuditService.setPasswordEmailAudit(userCN, userGUID, call)
        logger.atInfo().addKeyValue("userCN", userCN).log("Sent new-user email")
    }

    suspend fun sendNoUserEmail(emailAddress: String) {
        logger.atInfo().addKeyValue("emailAddress", emailAddress).log("Sending no-user-account email")
        sendTemplateEmail(
            "no-user-account",
            EmailContacts(
                emailAddress,
                emailAddress,
                emailConfig
            ),
            "DLUHC Delta - No User Account",
            mapOf("deltaUrl" to deltaConfig.deltaWebsiteUrl)
        )
        logger.atInfo().addKeyValue("emailAddress", emailAddress).log("Sent no-user-account email")
    }

    suspend fun sendNotYetEnabledEmail(user: LdapUser, token: String, call: ApplicationCall) {
        sendNotYetEnabledEmail(
            user.firstName,
            token,
            user.cn,
            user.getGUID(),
            EmailContacts(user.email!!, user.fullName, emailConfig),
            call,
        )
    }

    private suspend fun sendNotYetEnabledEmail(
        firstName: String,
        token: String,
        userCN: String,
        userGUID: UUID,
        contacts: EmailContacts,
        call: ApplicationCall,
    ) {
        sendTemplateEmail(
            "not-yet-enabled-user",
            contacts,
            "DLUHC Delta - Set Your Password",
            mapOf(
                "deltaUrl" to deltaConfig.deltaWebsiteUrl,
                "userFirstName" to firstName,
                "setPasswordUrl" to getSetPasswordURL(
                    token,
                    userCN,
                    authServiceConfig.serviceUrl
                )
            )
        )
        userAuditService.setPasswordEmailAudit(userCN, userGUID, call)
        logger.atInfo().addKeyValue("userCN", userCN).log("Sent not-yet-enabled-user email")
    }

    suspend fun sendPasswordNeverSetEmail(user: LdapUser, token: String, call: ApplicationCall) {
        sendPasswordNeverSetEmail(
            user.firstName,
            token,
            user.cn,
            user.getGUID(),
            EmailContacts(user.email!!, user.fullName, emailConfig),
            call,
        )
    }

    private suspend fun sendPasswordNeverSetEmail(
        firstName: String,
        token: String,
        userCN: String,
        userGUID: UUID,
        contacts: EmailContacts,
        call: ApplicationCall,
    ) {
        sendTemplateEmail(
            "password-never-set",
            contacts,
            "DLUHC Delta - Set Password",
            mapOf(
                "deltaUrl" to deltaConfig.deltaWebsiteUrl,
                "setPasswordUrl" to getSetPasswordURL(
                    token,
                    userCN,
                    authServiceConfig.serviceUrl
                ),
                "userFirstName" to firstName,
            )
        )
        userAuditService.setPasswordEmailAudit(userCN, userGUID, call)
        logger.atInfo().addKeyValue("userCN", userCN).log("Sent password-never-set email")
    }

    suspend fun sendResetPasswordEmail(
        user: LdapUser,
        token: String,
        triggeringAdminSession: OAuthSession?,
        userLookupService: UserLookupService, // TODO DT-976-2 - remove once GUID is definitely in session
        call: ApplicationCall
    ) {
        sendResetPasswordEmail(
            user.firstName,
            token,
            user.cn,
            user.getGUID(),
            triggeringAdminSession,
            userLookupService,
            EmailContacts(user.email!!, user.fullName, emailConfig),
            call,
        )
    }

    private suspend fun sendResetPasswordEmail(
        firstName: String,
        token: String,
        userCN: String,
        userGUID: UUID,
        triggeringAdminSession: OAuthSession?,
        userLookupService: UserLookupService, // TODO DT-976-2 - remove once GUID is definitely in session
        contacts: EmailContacts,
        call: ApplicationCall,
    ) {
        sendTemplateEmail(
            "reset-password",
            contacts,
            "DLUHC Delta - Reset Your Password",
            mapOf(
                "deltaUrl" to deltaConfig.deltaWebsiteUrl,
                "userFirstName" to firstName,
                "resetPasswordUrl" to getResetPasswordURL(
                    token,
                    userCN,
                    authServiceConfig.serviceUrl
                )
            )
        )
        if (triggeringAdminSession != null) userAuditService.adminResetPasswordEmailAudit(
            userCN,
            userGUID,
            triggeringAdminSession.userCn,
            triggeringAdminSession.getUserGUID(userLookupService),
            call
        )
        else userAuditService.resetPasswordEmailAudit(userCN, userGUID, call)

        logger.atInfo().addKeyValue("userCN", userCN).log("Sent reset-password email")
    }

    suspend fun sendEmailForUserAddedToDCLGInAccessGroup(
        userEmail: String,
        userName: String,
        actingUserEmail: String,
        recipients: List<EmailRecipient>,
        accessGroupDisplayName: String,
    ) {
        sendTemplateEmail(
            "user-added-to-dclg-in-access-group",
            EmailContacts(recipients, emailConfig),
            "Delta: DLUHC user has been added to collection group '$accessGroupDisplayName'",
            mapOf(
                "deltaUrl" to deltaConfig.deltaWebsiteUrl,
                "userFullName" to userName,
                "userEmailAddress" to userEmail,
                "actingUserEmail" to actingUserEmail,
                "accessGroupName" to accessGroupDisplayName
            )
        )

        logger.atInfo().addKeyValue("userEmail", userEmail).addKeyValue("accessGroupName", accessGroupDisplayName)
            .addKeyValue("emailRecipients", recipients.joinToString(";") { it.email })
            .log("Sent dluhc-user-added-to-collection email")
    }
}

class EmailRecipient(val email: String, val name: String)

class EmailContacts(
    private val recipients: List<EmailRecipient>,
    emailConfig: EmailConfig,
) {
    constructor(toEmail: String, toName: String, emailConfig: EmailConfig) : this(
        listOf(
            EmailRecipient(
                toEmail,
                toName
            )
        ), emailConfig
    )

    private val fromEmail: String = emailConfig.fromEmailAddress
    private val fromName: String = emailConfig.fromEmailName
    private val replyToEmail: String = emailConfig.replyToEmailAddress
    private val replyToName: String = emailConfig.replyToEmailName

    fun getTo(): Array<Address> {
        return recipients.map { InternetAddress(it.email, it.name, "UTF-8") }.toTypedArray()
    }

    fun getFrom(): Address {
        return InternetAddress(fromEmail, fromName, "UTF-8")
    }

    fun getReplyTo(): Address {
        return InternetAddress(replyToEmail, replyToName, "UTF-8")
    }
}
