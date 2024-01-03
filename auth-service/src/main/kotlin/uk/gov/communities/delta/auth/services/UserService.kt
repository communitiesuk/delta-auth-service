package uk.gov.communities.delta.auth.services

import com.fasterxml.jackson.annotation.JsonProperty
import org.slf4j.LoggerFactory
import uk.gov.communities.delta.auth.config.LDAPConfig
import uk.gov.communities.delta.auth.controllers.external.ResetPasswordException
import uk.gov.communities.delta.auth.utils.randomBase64
import java.io.UnsupportedEncodingException
import javax.naming.directory.*

class UserService(
    private val ldapServiceUserBind: LdapServiceUserBind,
    private val userLookupService: UserLookupService,
) {

    private val logger = LoggerFactory.getLogger(javaClass)

    suspend fun createUser(adUser: ADUser) {
        try {
            addUserToAD(adUser)
        } catch (e: Exception) {
            logger.atError().addKeyValue("UserDN", adUser.dn).log("Error creating user", e)
            throw e
        }
    }

    private suspend fun addUserToAD(adUser: ADUser) {
        val container: Attributes = BasicAttributes()
        container.put(adUser.objClasses)
        container.put(BasicAttribute("userPrincipalName", adUser.userPrincipalName))
        container.put(BasicAttribute("cn", adUser.cn))
        container.put(BasicAttribute("sn", adUser.sn))
        container.put(BasicAttribute("givenName", adUser.givenName))
        container.put(BasicAttribute("mail", adUser.mail))
        container.put(BasicAttribute("st", adUser.notificationStatus))
        container.put(BasicAttribute("userAccountControl", adUser.userAccountControl))

        if (adUser.comment != null) container.put(BasicAttribute("comment", adUser.comment))
        if (adUser.telephone != null) container.put(BasicAttribute("telephoneNumber", adUser.telephone))
        if (adUser.mobile != null) container.put(BasicAttribute("mobile", adUser.mobile))
        if (adUser.reasonForAccess != null) container.put(BasicAttribute("description", adUser.reasonForAccess))
        if (adUser.position != null) container.put(BasicAttribute("title", adUser.position))

        if (adUser.password != null) container.put(ADUser.getPasswordAttribute(adUser.password!!))

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

        constructor(ldapConfig: LDAPConfig, registration: Registration, ssoUser: Boolean) {
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
            ssoUser: Boolean,
        ) {
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
            this.reasonForAccess =
                if (deltaUserDetails.reasonForAccess.isNullOrEmpty()) null else deltaUserDetails.reasonForAccess
            this.position = if (deltaUserDetails.position.isNullOrEmpty()) null else deltaUserDetails.position
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
            return this.givenName + this.sn
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

    data class DeltaUserDetails(
        @JsonProperty("id") val id: String,
        @JsonProperty("enabled") val enabled: Boolean,
        @JsonProperty("email") val email: String,
        @JsonProperty("lastName") val lastName: String,
        @JsonProperty("firstName") val firstName: String,
        @JsonProperty("telephone") val telephone: String?,
        @JsonProperty("mobile") val mobile: String?,
        @JsonProperty("position") val position: String?,
        @JsonProperty("reasonForAccess") val reasonForAccess: String?,
        @JsonProperty("accessGroups") val accessGroups: Array<String>,
        @JsonProperty("accessGroupDelegates") val accessGroupDelegates: Array<String>,
        @JsonProperty("accessGroupOrganisations") val accessGroupOrganisations: Map<String, Array<String>>,
        @JsonProperty("roles") val roles: Array<String>,
        @JsonProperty("externalRoles") val externalRoles: Array<String>,
        @JsonProperty("organisations") val organisations: Array<String>,
        @JsonProperty("comment") val comment: String?,
        @JsonProperty("classificationType") val classificationType: String?,
    )
}
