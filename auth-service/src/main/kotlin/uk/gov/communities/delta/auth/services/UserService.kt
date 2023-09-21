package uk.gov.communities.delta.auth.services

import com.google.common.base.Strings
import org.slf4j.LoggerFactory
import uk.gov.communities.delta.auth.config.LDAPConfig
import java.io.UnsupportedEncodingException
import javax.naming.directory.*

class UserService(
    private val ldapService: LdapService,
    private val ldapConfig: LDAPConfig,
    private val groupService: GroupService,
) {

    private val logger = LoggerFactory.getLogger(javaClass)

    suspend fun createUser(adUser: ADUser) {
        try {
            addUserToAD(adUser)
        } catch (e: Exception) {
            logger.error("Error creating user with dn {}", adUser.dn, e)
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

        ldapService.useServiceUserBind {
            try {
                it.createSubcontext(adUser.dn, container)
            } catch (e: Exception) {
                logger.error("Problem creating user", e)
                throw e
            }
        }
    }

    suspend fun addUserToGroup(adUser: ADUser, groupName: String) {
        val groupDN = ldapConfig.groupDnFormat.format(groupName)

        if (!groupService.groupExists(groupDN)) {
            groupService.createGroup(groupName)
        }
        ldapService.useServiceUserBind {
            val member = BasicAttribute("member", adUser.dn)
            val modificationItems = arrayOf(ModificationItem(DirContext.ADD_ATTRIBUTE, member))
            it.modifyAttributes(groupDN, modificationItems)
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
        ldapService.useServiceUserBind {
            try {
                it.modifyAttributes(userDN, modificationItems)
            } catch (e: Exception) {
                throw e
            }
        }
    }

    class ADUser(registration: Registration, ssoUser: Boolean, private val ldapConfig: LDAPConfig ) {
        var cn: String = emailToCN(registration.emailAddress)
        var givenName: String = registration.firstName
        var sn: String = registration.lastName
        var mail: String = registration.emailAddress
        var userAccountControl: String = accountFlags(ssoUser)
        var dn: String = cnToDN(cn)
        var userPrincipalName: String = cnToPrincipalName(cn)
        var st: String = "active"
        var objClasses = objClasses()
        var password = if (ssoUser) randomBase64(20) else null
        var comment = if (ssoUser) "Created via SSO" else null

        private fun objClasses(): Attribute {
            val objClasses: Attribute = BasicAttribute("objectClass")
            objClasses.add("user")
            objClasses.add("organizationalPerson")
            objClasses.add("person")
            objClasses.add("top")
            return objClasses
        }

        private fun emailToCN(email: String): String {
            return Strings.nullToEmpty(email).replace("@", "!")
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
                return  if (enabled) {
                    NORMAL_ACCOUNT_FLAG.toString()
                } else {
                    return (NORMAL_ACCOUNT_FLAG + ACCOUNTDISABLE_FLAG).toString()
                }
            }

            fun getPasswordAttribute(password: String): Attribute {
                lateinit var bytes: ByteArray
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