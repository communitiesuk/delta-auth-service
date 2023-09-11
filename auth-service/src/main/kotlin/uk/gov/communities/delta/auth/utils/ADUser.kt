package uk.gov.communities.delta.auth.utils

import com.google.common.base.Strings
import uk.gov.communities.delta.auth.config.LDAPConfig
import uk.gov.communities.delta.auth.services.Registration
import javax.naming.directory.Attribute
import javax.naming.directory.BasicAttribute

class ADUser(registration: Registration, val ldapConfig: LDAPConfig) {
    var cn: String = emailToCN(registration.emailAddress)
    var givenName: String = registration.firstName
    var sn: String = registration.lastName
    var mail: String = registration.emailAddress
    var userAccountControl: String = newAccountFlags
    var dn: String = cnToDN(cn)
    var userPrincipalName: String = cnToPrincipalName(cn)
    var st: String = "active"
    var objClasses = objClasses()

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
        const val newAccountFlags = (NORMAL_ACCOUNT_FLAG + ACCOUNTDISABLE_FLAG).toString()
    }
}