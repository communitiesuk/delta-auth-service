package uk.gov.communities.delta.auth.utils

import uk.gov.communities.delta.auth.config.LDAPConfig
import javax.naming.directory.Attribute
import javax.naming.directory.BasicAttribute

class ADGroup(val cn: String, private val ldapConfig: LDAPConfig){
    val dn: String = cnToDN(cn)
    val objectClasses = objClasses()

    private fun objClasses(): Attribute {
        val objClasses: Attribute = BasicAttribute("objectClass")
        objClasses.add("group")
        objClasses.add("top")
        return objClasses
    }

    private fun cnToDN(cn: String): String {
        return String.format(ldapConfig.groupDnFormat, cn)
    }
}