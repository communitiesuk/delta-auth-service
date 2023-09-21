package uk.gov.communities.delta.auth.services

import org.slf4j.LoggerFactory
import uk.gov.communities.delta.auth.config.LDAPConfig
import javax.naming.directory.Attribute
import javax.naming.directory.Attributes
import javax.naming.directory.BasicAttribute
import javax.naming.directory.BasicAttributes

class GroupService(
    private val ldapService: LdapService,
    private val ldapConfig: LDAPConfig,
) {

    private val logger = LoggerFactory.getLogger(javaClass)

    suspend fun createGroup(groupName: String) {
        try {
            addGroupToAD(ADGroup(groupName, ldapConfig))
        } catch (e: Exception) {
            logger.error("Problem creating group with name {} in AD", groupName, e)
            throw e
        }
    }

    suspend fun groupExists(groupDn: String): Boolean {
        var attributes: Attributes = BasicAttributes()
        ldapService.useServiceUserBind {
            attributes =
                it.getAttributes(
                    groupDn,
                    arrayOf("cn")
                )
        }
        return attributes.get("cn") != null
    }

    private suspend fun addGroupToAD(adGroup: ADGroup) {
        val container: Attributes = BasicAttributes()
        container.put(adGroup.objectClasses)
        container.put(BasicAttribute("cn", adGroup.cn))
        ldapService.useServiceUserBind {
            it.createSubcontext(adGroup.dn, container)
        }
    }

    class ADGroup(val cn: String, private val ldapConfig: LDAPConfig) {
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
}