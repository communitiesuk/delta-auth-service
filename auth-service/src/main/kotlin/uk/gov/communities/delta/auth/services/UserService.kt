package uk.gov.communities.delta.auth.services

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
        container.put(BasicAttribute("st", adUser.st))
        container.put(BasicAttribute("userAccountControl", adUser.userAccountControl))
        if (adUser.password != null) container.put(ADUser.getPasswordAttribute(adUser.password!!))
        if (adUser.comment != null) container.put(BasicAttribute("comment", adUser.comment))

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

    class ADUser(registration: Registration, ssoUser: Boolean, private val ldapConfig: LDAPConfig) {
        var cn: String = LDAPConfig.emailToCN(registration.emailAddress)
        var givenName: String = registration.firstName
        var sn: String = registration.lastName
        var mail: String = registration.emailAddress
        var userAccountControl: String = accountFlags(ssoUser)
        var dn: String = cnToDN(cn)
        var userPrincipalName: String = cnToPrincipalName(cn)
        var st: String = "active"
        var objClasses = objClasses()
        var password = if (ssoUser) randomBase64(18) else null
        var comment = if (ssoUser) "Created via SSO" else null

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
