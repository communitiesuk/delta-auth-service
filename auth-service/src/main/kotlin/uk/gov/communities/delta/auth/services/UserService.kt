package uk.gov.communities.delta.auth.services

import io.ktor.server.application.*
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import org.slf4j.LoggerFactory
import uk.gov.communities.delta.auth.config.AzureADSSOClient
import uk.gov.communities.delta.auth.config.LDAPConfig
import uk.gov.communities.delta.auth.controllers.external.ResetPasswordException
import uk.gov.communities.delta.auth.controllers.internal.DeltaUserDetailsRequest
import uk.gov.communities.delta.auth.repositories.LdapUser
import uk.gov.communities.delta.auth.utils.randomBase64
import java.io.UnsupportedEncodingException
import javax.naming.directory.*

class UserService(
    private val ldapServiceUserBind: LdapServiceUserBind,
    private val userLookupService: UserLookupService,
    private val userAuditService: UserAuditService,
) {

    private val logger = LoggerFactory.getLogger(javaClass)

    suspend fun createUser(
        adUser: ADUser,
        ssoClient: AzureADSSOClient?,
        triggeringAdminSession: OAuthSession?,
        call: ApplicationCall,
        azureUserObjectId: String? = null,
    ) {
        val attributes = getAttributes(adUser)
        try {
            addUserToAD(adUser, attributes)
        } catch (e: Exception) {
            logger.atError().addKeyValue("UserDN", adUser.dn).log("Error creating user", e)
            throw e
        }
        auditUserCreation(
            adUser.cn,
            ssoClient,
            triggeringAdminSession,
            call,
            getAuditData(attributes, ssoClient, azureUserObjectId),
        )
    }

    suspend fun updateUser(
        ldapUser: LdapUser,
        modifications: Array<ModificationItem>,
        triggeringAdminSession: OAuthSession?,
        call: ApplicationCall,
    ) {
        try {
            updateUserOnAD(ldapUser.dn, modifications)
        } catch (e: Exception) {
            logger.atError().addKeyValue("UserDN", ldapUser.dn).log("Error updating user", e)
            throw e
        }
        auditUserUpdate(ldapUser.cn, triggeringAdminSession, call, getAuditData(modifications))
    }

    suspend fun updateUsername(
        ldapUser: LdapUser,
        username: String,
        triggeringAdminSession: OAuthSession?,
        call: ApplicationCall,
    ) {
        // TODO 694 does this need any special handling? !/@ substitution?
        val usernameModification = ModificationItem(DirContext.REPLACE_ATTRIBUTE, BasicAttribute("id", username))
        val modificationArray = arrayOf(usernameModification)
        try {
            updateUserOnAD(ldapUser.dn, modificationArray)
        } catch (e: Exception) {
            logger.atError().addKeyValue("UserDN", ldapUser.dn).log("Error changing username", e)
            throw e
        }
        auditUserUpdate(ldapUser.cn, triggeringAdminSession, call, getAuditData(modificationArray))
    }

    private suspend fun auditUserCreation(
        userCN: String,
        ssoClient: AzureADSSOClient?,
        triggeringAdminSession: OAuthSession?,
        call: ApplicationCall,
        auditData: Map<String, String>,
    ) {
        val ssoUser = ssoClient?.required == true
        val encodedAuditData = Json.encodeToString(auditData)
        if (triggeringAdminSession != null) {
            if (ssoUser) userAuditService.ssoUserCreatedByAdminAudit(
                userCN,
                triggeringAdminSession.userCn,
                call,
                encodedAuditData
            )
            else userAuditService.userCreatedByAdminAudit(userCN, triggeringAdminSession.userCn, call, encodedAuditData)
        } else if (ssoUser) userAuditService.userCreatedBySSOAudit(
            userCN,
            call,
            encodedAuditData
        ) else userAuditService.userSelfRegisterAudit(userCN, call, encodedAuditData)
    }

    private suspend fun auditUserUpdate(
        userCN: String,
        triggeringAdminSession: OAuthSession?,
        call: ApplicationCall,
        auditData: Map<String, String>,
    ) {
        val encodedAuditData = Json.encodeToString(auditData)
        if (triggeringAdminSession != null)
            userAuditService.userUpdateByAdminAudit(userCN, triggeringAdminSession.userCn, call, encodedAuditData)
        else
            userAuditService.userUpdateAudit(userCN, call, encodedAuditData)
    }

    private fun getAuditData(
        attributes: Attributes,
        ssoClient: AzureADSSOClient? = null,
        azureUserObjectId: String? = null
    ): Map<String, String> {
        val auditData = mutableMapOf<String, String>()

        attributes.all.asIterator().forEach {
            addToAuditData(auditData, it)
        }
        addSSODetailsToAuditData(auditData, ssoClient, azureUserObjectId)

        return auditData
    }

    private fun getAuditData(
        modifications: Array<ModificationItem>,
        ssoClient: AzureADSSOClient? = null,
        azureUserObjectId: String? = null
    ): Map<String, String> {
        val auditData = mutableMapOf<String, String>()

        modifications.forEach {
            when (it.modificationOp) {
                DirContext.ADD_ATTRIBUTE -> addToAuditData(auditData, it.attribute)
                DirContext.REPLACE_ATTRIBUTE -> addToAuditData(auditData, it.attribute)
                DirContext.REMOVE_ATTRIBUTE -> auditData[it.attribute.id] = ""
            }
        }
        addSSODetailsToAuditData(auditData, ssoClient, azureUserObjectId)

        return auditData
    }

    private fun addSSODetailsToAuditData(
        auditData: MutableMap<String, String>,
        ssoClient: AzureADSSOClient?,
        azureUserObjectId: String?
    ) {
        val ssoUser = ssoClient?.required == true
        if (ssoUser) {
            auditData["ssoClientInternalId"] = ssoClient!!.internalId
            if (azureUserObjectId != null) auditData["azureObjectId"] = azureUserObjectId
        }
    }

    private fun addToAuditData(auditData: MutableMap<String, String>, attribute: Attribute) {
        if (attribute.id.equals("unicodePwd")) auditData["SettingPassword"] = true.toString()
        else auditData[attribute.id] = attribute.get().toString()
    }

    private fun getAttributes(adUser: ADUser): Attributes {
        val attributes: Attributes = BasicAttributes()
        attributes.put(adUser.objClasses)
        attributes.put(BasicAttribute("userPrincipalName", adUser.userPrincipalName))
        attributes.put(BasicAttribute("cn", adUser.cn))
        attributes.put(BasicAttribute("sn", adUser.sn))
        attributes.put(BasicAttribute("givenName", adUser.givenName))
        attributes.put(BasicAttribute("mail", adUser.mail))
        attributes.put(BasicAttribute("st", adUser.notificationStatus))
        attributes.put(BasicAttribute("userAccountControl", adUser.userAccountControl))

        adUser.comment?.let { attributes.put(BasicAttribute("comment",it)) }
        adUser.telephone?.let { attributes.put(BasicAttribute("telephoneNumber",it)) }
        adUser.mobile?.let { attributes.put(BasicAttribute("mobile",it)) }
        adUser.reasonForAccess?.let { attributes.put(BasicAttribute("description",it)) }
        adUser.position?.let { attributes.put(BasicAttribute("title",it)) }

        adUser.password?.let { attributes.put(ADUser.getPasswordAttribute(it)) }

        return attributes
    }

    private suspend fun addUserToAD(adUser: ADUser, attributes: Attributes) {
        val enabled = adUser.userAccountControl == ADUser.accountFlags(true)
        if (enabled && adUser.password == null) {
            throw Exception("Trying to create enabled user with no password")
        } else {
            ldapServiceUserBind.useServiceUserBind {
                try {
                    it.createSubcontext(adUser.dn, attributes)
                    logger.atInfo().addKeyValue("UserDN", adUser.dn)
                        .log("{} user created", if (enabled) "Enabled" else "Disabled")
                } catch (e: Exception) {
                    logger.atError().addKeyValue("UserDN", adUser.dn).log("Problem creating user", e)
                    throw e
                }
            }
        }
    }

    private suspend fun updateUserOnAD(
        userDN: String,
        modifications: Array<ModificationItem>,
    ) {
        ldapServiceUserBind.useServiceUserBind {
            try {
                it.modifyAttributes(userDN, modifications)
                logger.atInfo().addKeyValue("UserDN", userDN).log("User updated")
            } catch (e: Exception) {
                logger.atError().addKeyValue("UserDN", userDN).log("Problem updating user", e)
                throw e
            }
        }
    }

    suspend fun setPasswordAndEnable(userDN: String, password: String) {
        val modificationItems = arrayOf(
            ModificationItem(DirContext.REPLACE_ATTRIBUTE, ADUser.getPasswordAttribute(password)),
            ModificationItem(
                DirContext.REPLACE_ATTRIBUTE,
                BasicAttribute("userAccountControl", ADUser.accountFlags(true))
            )
        )
        ldapServiceUserBind.useServiceUserBind {
            it.modifyAttributes(userDN, modificationItems)
            logger.atInfo().addKeyValue("UserDN", userDN).log("Account enabled and password set")
        }
    }

    // Enabling the account and notifications would ideally be separate,
    // but for now we do both to keep compatibility with Delta
    suspend fun enableAccountAndNotifications(userDN: String) {
        val modificationItems = arrayOf(
            ModificationItem(
                DirContext.REPLACE_ATTRIBUTE,
                BasicAttribute("userAccountControl", ADUser.accountFlags(true))
            ),
            ModificationItem(
                DirContext.REPLACE_ATTRIBUTE,
                BasicAttribute("st", "active")
            )
        )
        ldapServiceUserBind.useServiceUserBind {
            it.modifyAttributes(userDN, modificationItems)
            logger.atInfo().addKeyValue("UserDN", userDN).log("Account and notifications enabled")
        }
    }

    suspend fun disableAccountAndNotifications(userDN: String) {
        val modificationItems = arrayOf(
            ModificationItem(
                DirContext.REPLACE_ATTRIBUTE,
                BasicAttribute("userAccountControl", ADUser.accountFlags(false))
            ),
            ModificationItem(
                DirContext.REPLACE_ATTRIBUTE,
                BasicAttribute("st", "inactive")
            )
        )
        ldapServiceUserBind.useServiceUserBind {
            it.modifyAttributes(userDN, modificationItems)
            logger.atInfo().addKeyValue("UserDN", userDN).log("Account and notifications disabled")
        }
    }

    suspend fun resetPassword(userDN: String, password: String) {
        val modificationItems = arrayOf(
            ModificationItem(DirContext.REPLACE_ATTRIBUTE, ADUser.getPasswordAttribute(password)),
            // Unlock account if it is locked
            ModificationItem(DirContext.REPLACE_ATTRIBUTE, BasicAttribute("lockoutTime", "0")),
        )
        val accountEnabled = userLookupService.lookupUserByDN(userDN).accountEnabled
        if (!accountEnabled) throw ResetPasswordException(
            "disabled_user_on_password_reset",
            "Trying to reset password for a disabled user $userDN",
            "Your account is disabled, your password can not be reset. Please contact the service desk"
        )
        else ldapServiceUserBind.useServiceUserBind {
            try {
                it.modifyAttributes(userDN, modificationItems)
                logger.atInfo().addKeyValue("userDN", userDN).log("Password reset")
            } catch (e: Exception) {
                logger.atError().addKeyValue("userDN", userDN).log("Error occurred on setting password", e)
                throw e
            }
        }
    }

    class ADUser {
        var ldapConfig: LDAPConfig
            private set
        var cn: String
            private set
        var givenName: String
            private set
        var sn: String
            private set
        var mail: String
            private set
        var userAccountControl: String
            private set
        var dn: String
            private set
        var userPrincipalName: String
            private set
        var notificationStatus: String
            private set
        var password: String? = null
            private set
        var comment: String? = null
            private set
        var telephone: String? = null
            private set
        var mobile: String? = null
            private set
        var reasonForAccess: String? = null
            private set
        var position: String? = null
            private set
        var objClasses: Attribute = objClasses()

        constructor(ldapConfig: LDAPConfig, registration: Registration, ssoClient: AzureADSSOClient?) {
            val ssoUser = ssoClient?.required ?: false
            this.ldapConfig = ldapConfig
            this.cn = LDAPConfig.emailToCN(registration.emailAddress)
            this.givenName = registration.firstName
            this.sn = registration.lastName
            this.mail = registration.emailAddress
            this.userAccountControl = accountFlags(ssoUser)
            this.dn = cnToDN(cn)
            this.userPrincipalName = cnToPrincipalName(cn)
            this.notificationStatus = "active"
            this.password = if (ssoUser) randomBase64(18) else null
            this.comment = if (ssoUser) "Created via SSO" else null
        }

        constructor(
            ldapConfig: LDAPConfig,
            deltaUserDetails: DeltaUserDetailsRequest,
            ssoClient: AzureADSSOClient?,
        ) {
            val ssoUser = ssoClient?.required ?: false
            this.ldapConfig = ldapConfig
            this.cn = LDAPConfig.emailToCN(deltaUserDetails.email)
            this.givenName = deltaUserDetails.firstName
            this.sn = deltaUserDetails.lastName
            this.mail = deltaUserDetails.email
            this.userAccountControl = accountFlags(ssoUser)
            this.dn = cnToDN(cn)
            this.userPrincipalName = cnToPrincipalName(cn)
            this.notificationStatus = "active"
            this.password = if (ssoUser) randomBase64(18) else null
            this.comment = if (deltaUserDetails.comment.isNullOrEmpty()) null else deltaUserDetails.comment
            this.telephone = if (deltaUserDetails.telephone.isNullOrEmpty()) null else deltaUserDetails.telephone
            this.mobile = if (deltaUserDetails.mobile.isNullOrEmpty()) null else deltaUserDetails.mobile
            this.position = if (deltaUserDetails.position.isNullOrEmpty()) null else deltaUserDetails.position
            this.reasonForAccess =
                if (deltaUserDetails.reasonForAccess.isNullOrEmpty()) null else deltaUserDetails.reasonForAccess

        }

        private fun objClasses(): Attribute {
            val objClasses: Attribute = BasicAttribute("objectClass")
            objClasses.add("user")
            objClasses.add("organizationalPerson")
            objClasses.add("person")
            objClasses.add("top")
            return objClasses
        }

        private fun cnToDN(cn: String): String {
            return String.format(ldapConfig.deltaUserDnFormat, cn)
        }

        private fun cnToPrincipalName(cn: String): String {
            return String.format("%s@%s", cn, ldapConfig.domainRealm)
        }

        fun getDisplayName(): String {
            return "${this.givenName} ${this.sn}"
        }

        companion object {
            private const val NORMAL_ACCOUNT_FLAG = 512
            private const val ACCOUNTDISABLE_FLAG = 2
            fun accountFlags(enabled: Boolean): String {
                return if (enabled) {
                    NORMAL_ACCOUNT_FLAG.toString()
                } else {
                    return (NORMAL_ACCOUNT_FLAG + ACCOUNTDISABLE_FLAG).toString()
                }
            }

            fun getPasswordAttribute(password: String): Attribute {
                val bytes: ByteArray
                try {
                    val quoted = '"'.toString() + password + '"'
                    bytes = quoted.toByteArray(charset("UTF-16LE"))
                } catch (ex: UnsupportedEncodingException) {
                    throw Error(ex)
                }

                return BasicAttribute("unicodePwd", bytes)
            }
        }
    }
}
