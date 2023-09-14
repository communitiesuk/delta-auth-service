package uk.gov.communities.delta.auth.utils

import com.google.common.base.Strings
import uk.gov.communities.delta.auth.config.LDAPConfig
import uk.gov.communities.delta.auth.services.Registration
import uk.gov.communities.delta.auth.services.randomBase64
import java.io.UnsupportedEncodingException
import javax.naming.directory.Attribute
import javax.naming.directory.BasicAttribute

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