package uk.gov.communities.delta.auth.services

import io.ktor.server.application.*
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import org.slf4j.LoggerFactory
import uk.gov.communities.delta.auth.config.AzureADSSOClient
import uk.gov.communities.delta.auth.config.LDAPConfig
import uk.gov.communities.delta.auth.controllers.external.ResetPasswordException
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
        try {
            addUserToAD(adUser)
        } catch (e: Exception) {
            logger.atError().addKeyValue("UserDN", adUser.dn).log("Error creating user", e)
            throw e
        }
        auditUserCreation(adUser.cn, ssoClient, triggeringAdminSession, call, getAuditData(adUser), azureUserObjectId)
    }

    private suspend fun auditUserCreation(
        userCN: String,
        ssoClient: AzureADSSOClient?,
        triggeringAdminSession: OAuthSession?,
        call: ApplicationCall,
        auditData: MutableMap<String, String>,
        azureUserObjectId: String?,
    ) {
        val ssoUser = ssoClient?.required == true
        if (ssoUser) {
            auditData["ssoClientInternalId"] = ssoClient!!.internalId
            if (azureUserObjectId != null) auditData["azureObjectId"] = azureUserObjectId
        }
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

    private fun getAuditData(adUser: ADUser): MutableMap<String, String> {
        val auditData = mutableMapOf<String, String>()
        auditData["userPrincipalName"] = adUser.userPrincipalName
        auditData["cn"] = adUser.cn
        auditData["sn"] = adUser.sn
        auditData["givenName"] = adUser.givenName
        auditData["mail"] = adUser.mail
        auditData["st"] = adUser.notificationStatus
        auditData["userAccountControl"] = adUser.userAccountControl

        adUser.comment?.let { auditData["comment"] = it }
        adUser.telephone?.let { auditData["telephoneNumber"] = it }
        adUser.mobile?.let { auditData["mobile"] = it }
        adUser.reasonForAccess?.let { auditData["description"] = it }
        adUser.position?.let { auditData["title"] = it }

        auditData["HasPassword"] = (adUser.password != null).toString()

        return auditData
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

    private suspend fun addUserToAD(adUser: ADUser) {
        val container = getAttributes(adUser)

        val enabled = adUser.userAccountControl == ADUser.accountFlags(true)
        if (enabled && adUser.password == null) {
            throw Exception("Trying to create user with no password")
        } else {
            ldapServiceUserBind.useServiceUserBind {
                try {
                    it.createSubcontext(adUser.dn, container)
                    logger.atInfo().addKeyValue("UserDN", adUser.dn)
                        .log("{} user created", if (enabled) "Enabled" else "Disabled")
                } catch (e: Exception) {
                    logger.atError().addKeyValue("UserDN", adUser.dn).log("Problem creating user", e)
                    throw e
                }
            }
        }
    }

    suspend fun setPassword(userDN: String, password: String) {
        val modificationItems = arrayOf(
            ModificationItem(DirContext.REPLACE_ATTRIBUTE, ADUser.getPasswordAttribute(password)),
            ModificationItem(
                DirContext.REPLACE_ATTRIBUTE,
                BasicAttribute("userAccountControl", ADUser.accountFlags(true))
            )
        )
        ldapServiceUserBind.useServiceUserBind {
            try {
                it.modifyAttributes(userDN, modificationItems)
                logger.atInfo().addKeyValue("UserDN", userDN).log("Account enabled and password set")
            } catch (e: Exception) {
                throw e
            }
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
            deltaUserDetails: DeltaUserDetails,
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

    @Serializable
    data class DeltaUserDetails(
        @SerialName("id") val id: String, //Not used anywhere yet
        @SerialName("enabled") val enabled: Boolean, //Always false for user creation - not used anywhere yet
        @SerialName("email") val email: String,
        @SerialName("lastName") val lastName: String,
        @SerialName("firstName") val firstName: String,
        @SerialName("telephone") val telephone: String? = null,
        @SerialName("mobile") val mobile: String? = null,
        @SerialName("position") val position: String? = null,
        @SerialName("reasonForAccess") val reasonForAccess: String? = null,
        @SerialName("accessGroups") val accessGroups: Array<String>,
        @SerialName("accessGroupDelegates") val accessGroupDelegates: Array<String>,
        @SerialName("accessGroupOrganisations") val accessGroupOrganisations: Map<String, Array<String>>,
        @SerialName("roles") val roles: Array<String>,
        @SerialName("externalRoles") val externalRoles: Array<String>, //Not used anywhere yet
        @SerialName("organisations") val organisations: Array<String>,
        @SerialName("comment") val comment: String? = null,
        @SerialName("classificationType") val classificationType: String? = null, //Not used anywhere yet
    )
}
