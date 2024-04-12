package uk.gov.communities.delta.auth.services

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch
import org.slf4j.LoggerFactory
import uk.gov.communities.delta.auth.config.EmailConfig
import uk.gov.communities.delta.auth.config.LDAPConfig
import uk.gov.communities.delta.auth.repositories.LdapUser
import uk.gov.communities.delta.auth.repositories.searchPaged
import uk.gov.communities.delta.auth.utils.EmailAddressChecker
import javax.naming.directory.SearchControls
import kotlin.coroutines.CoroutineContext
import kotlin.time.Duration.Companion.seconds

/*
 * This class handles sending notification emails when users are given membership of the dclg organisation in an access group.
 * The recipients are the Lead Testers and Dataset Admins for that Access Group, see recipientsForAccessGroup below.
 * The emails are sent asynchronously from a separate coroutine.
 * See ticket DT-696 for details.
 */
class AccessGroupDCLGMembershipUpdateEmailService(
    private val ldapServiceUserBind: LdapServiceUserBind,
    private val ldapConfig: LDAPConfig,
    private val emailService: EmailService,
    private val emailConfig: EmailConfig,
) : CoroutineScope {
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

    override val coroutineContext: CoroutineContext
        get() = Dispatchers.IO + supervisorJob

    fun sendNotificationEmailsForUserAddedToDCLGGroup(
        user: UpdatedUser,
        actingUser: LdapUser,
        addedDclgAccessGroupName: String,
        addedDclgAccessGroupDisplayName: String?,
    ) {
        if (!emailConfig.dclgAccessGroupUpdateNotificationsEnabled) {
            return
        }

        launchSendEmailJob(
            user, actingUser, listOf(AccessGroup(addedDclgAccessGroupName, addedDclgAccessGroupDisplayName))
        )
    }

    fun sendNotificationEmailsForUserChange(
        user: UpdatedUser,
        actingUser: LdapUser,
        previousAccessGroups: Collection<AccessGroupRole>,
        newAccessGroups: Collection<AccessGroupRole>,
    ) {
        if (!emailConfig.dclgAccessGroupUpdateNotificationsEnabled) {
            return
        }

        val previousDclgGroups = previousAccessGroups.filter { it.organisationIds.contains("dclg") }.toSet()
        val newDclgGroups = newAccessGroups.filter { it.organisationIds.contains("dclg") }.toSet()

        val newGroups = newDclgGroups - previousDclgGroups
        if (newGroups.isEmpty()) return

        launchSendEmailJob(user, actingUser, newGroups.map { AccessGroup(it.name, it.displayName) })
    }

    private fun launchSendEmailJob(user: UpdatedUser, actingUser: LdapUser, addedGroups: Collection<AccessGroup>) {
        launch {
            try {
                for (group in addedGroups) {
                    sendEmailsForChangeToAccessGroup(group, user, actingUser.email ?: actingUser.cn)
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

    private suspend fun sendEmailsForChangeToAccessGroup(
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

        emailService.sendDLUHCUserAddedToUserGroupEmail(user.email, user.name, changeByUserEmail, usersToEmail, group.emailDisplayName())
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
