package uk.gov.communities.delta.auth.services

import io.opentelemetry.context.Context
import io.opentelemetry.extension.kotlin.asContextElement
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch
import kotlinx.coroutines.slf4j.MDCContext
import org.slf4j.LoggerFactory
import org.slf4j.MDC
import uk.gov.communities.delta.auth.config.EmailConfig
import uk.gov.communities.delta.auth.config.LDAPConfig
import uk.gov.communities.delta.auth.repositories.LdapUser
import uk.gov.communities.delta.auth.repositories.searchPaged
import uk.gov.communities.delta.auth.utils.EmailAddressChecker
import javax.naming.directory.SearchControls
import kotlin.time.Duration.Companion.seconds

/*
 * This class handles sending notification emails when users are given membership of the dclg organisation in an access group.
 * The recipients are the Lead Testers and Dataset Admins for that Access Group, see recipientsForAccessGroup below.
 * The emails are sent asynchronously from a separate coroutine.
 * See ticket DT-696 for details.
 *
 * When a user is updated either sendNotificationEmailsForChangeToUserAccessGroups should be called with both the
 * previous and new access groups,
 * or sendNotificationEmailsForUserAddedToDCLGInAccessGroup should be called for each access group where the user was
 * assigned the dclg organisation for the access group.
 */
class AccessGroupDCLGMembershipUpdateEmailService(
    private val ldapServiceUserBind: LdapServiceUserBind,
    private val ldapConfig: LDAPConfig,
    private val emailService: EmailService,
    private val emailConfig: EmailConfig,
) {
    private val supervisorJob = SupervisorJob()
    private val logger = LoggerFactory.getLogger(javaClass)
    private val emailChecker = EmailAddressChecker()

    private val defaultRecipients = emailConfig.dclgAccessGroupUpdateAdditionalRecipients.map {
        EmailRecipient(
            it,
            it.substringBefore('@')
        )
    }

    private data class AccessGroup(val adName: String, val displayName: String?) {
        fun emailDisplayName() = if (displayName.isNullOrBlank()) adName else "$displayName ($adName)"
    }

    data class UpdatedUser(val email: String, val name: String) {
        constructor(user: LdapUser) : this(user.email ?: user.cn.replace('!', '@'), user.fullName)
    }

    fun sendNotificationEmailsForUserAddedToDCLGInAccessGroup(
        user: UpdatedUser,
        actingUser: LdapUser,
        addedDCLGAccessGroupName: String,
        addedDCLGAccessGroupDisplayName: String?,
    ) {
        if (!emailConfig.dclgAccessGroupUpdateNotificationsEnabled) {
            return
        }

        launchSendEmailJob(
            user, actingUser, listOf(AccessGroup(addedDCLGAccessGroupName, addedDCLGAccessGroupDisplayName))
        )
    }

    fun sendNotificationEmailsForChangeToUserAccessGroups(
        user: UpdatedUser,
        actingUser: LdapUser,
        previousAccessGroups: Collection<AccessGroupRole>,
        newAccessGroups: Collection<AccessGroupRole>,
    ) {
        if (!emailConfig.dclgAccessGroupUpdateNotificationsEnabled) {
            return
        }

        val previousDCLGGroupNames = previousAccessGroups.filter { it.organisationIds.contains("dclg") }
            .map { it.name }.toSet()
        val newDCLGGroups = newAccessGroups.filter { it.organisationIds.contains("dclg") }

        val addedGroups = newDCLGGroups.filter { !previousDCLGGroupNames.contains(it.name) }
        if (addedGroups.isEmpty()) return

        launchSendEmailJob(user, actingUser, addedGroups.map { AccessGroup(it.name, it.displayName) })
    }

    private fun launchSendEmailJob(user: UpdatedUser, actingUser: LdapUser, addedGroups: Collection<AccessGroup>) {
        val mdcContextMap = MDC.getCopyOfContextMap() ?: mutableMapOf()
        mdcContextMap["backgroundJob"] = "SendAccessGroupDCLGMembershipUpdateEmail"

        CoroutineScope(supervisorJob + Dispatchers.IO + MDCContext(mdcContextMap) + Context.current().asContextElement()).launch {
            try {
                for (group in addedGroups) {
                    sendEmailsForAddedToDCLGInAccessGroup(group, user, actingUser.email ?: actingUser.cn)
                }
            } catch (e: Exception) {
                logger.error(
                    "Failed to send notification emails for change to user {}, they were added to groups {}",
                    user.email,
                    addedGroups.map { it },
                    e,
                )
            }
        }
    }

    private suspend fun sendEmailsForAddedToDCLGInAccessGroup(
        group: AccessGroup,
        user: UpdatedUser,
        changeByUserEmail: String,
    ) {
        val usersToEmail = defaultRecipients + recipientsForAccessGroup(group)
            .filter { it.email != user.email }
            .filter { emailChecker.hasValidFormat(it.email) }

        if (usersToEmail.isEmpty()) {
            logger.info("User added to dclg in group {}, but no-one to email", user.email)
            return
        }

        emailService.sendEmailForUserAddedToDCLGInAccessGroup(
            user.email,
            user.name,
            changeByUserEmail,
            usersToEmail,
            group.emailDisplayName()
        )
    }

    private suspend fun recipientsForAccessGroup(group: AccessGroup): List<EmailRecipient> {
        return ldapServiceUserBind.useServiceUserBind { ctx ->
            val searchDn = ldapConfig.deltaUserDnFormat.removePrefix("CN=%s,")
            val searchControls = SearchControls()
            searchControls.searchScope = SearchControls.ONELEVEL_SCOPE
            searchControls.timeLimit = 10.seconds.inWholeMilliseconds.toInt()
            searchControls.returningAttributes = arrayOf("mail", "givenName", "sn")

            ctx.searchPaged(
                searchDn,
                "(&" +
                    "(objectClass=user)" +
                    "(memberOf=${ldapConfig.groupDnFormat.format("datamart-delta-${group.adName}-dclg")})" +
                    "(userAccountControl=512)" + // Normal account, not disabled
                    // Lead Tester OR (Dataset Admin AND has access group delegated)
                    "(|" +
                    "(memberOf=${ldapConfig.groupDnFormat.format(DeltaSystemRole.LEAD_TESTERS.adCn())})" +
                    "(&" +
                    "(memberOf=${ldapConfig.groupDnFormat.format(DeltaSystemRole.DATASET_ADMINS.adCn())})" +
                    "(memberOf=${ldapConfig.groupDnFormat.format("datamart-delta-delegate-${group.adName}")})" +
                    ")" +
                    ")" +
                    ")",
                searchControls,
                pageSize = 200
            ) {
                val email = it.get("mail").get() as String
                val firstName = it.get("givenName")?.get() as String? ?: ""
                val surname = it.get("sn")?.get() as String? ?: ""
                EmailRecipient(email, "$firstName $surname")
            }
        }
    }
}
