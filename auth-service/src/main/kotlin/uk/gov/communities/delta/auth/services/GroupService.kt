package uk.gov.communities.delta.auth.services

import org.slf4j.LoggerFactory
import uk.gov.communities.delta.auth.config.LDAPConfig
import javax.naming.directory.*

class GroupService(
    private val ldapService: LdapService,
    private val ldapConfig: LDAPConfig,
) {

    private val logger = LoggerFactory.getLogger(javaClass)

    suspend fun createGroup(groupCN: String) {
        try {
            addGroupToAD(ADGroup(groupCN, ldapConfig))
        } catch (e: Exception) {
            logger.error("Problem creating group with cn {} in AD", groupCN, e)
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

    suspend fun addUserToGroup(adUser: UserService.ADUser, groupCN: String) {
        val groupDN = ldapConfig.groupDnFormat.format(groupCN)

        if (!groupExists(groupDN)) {
            createGroup(groupCN)
        }
        ldapService.useServiceUserBind {
            val member = BasicAttribute("member", adUser.dn)
            val modificationItems = arrayOf(ModificationItem(DirContext.ADD_ATTRIBUTE, member))
            it.modifyAttributes(groupDN, modificationItems)
            logger.info("User with dn {} added to group with dn {}", adUser.dn, groupDN)
        }
    }

    private suspend fun addGroupToAD(adGroup: ADGroup) {
        val container: Attributes = BasicAttributes()
        container.put(adGroup.objectClasses)
        container.put(BasicAttribute("cn", adGroup.cn))
        ldapService.useServiceUserBind {
            it.createSubcontext(adGroup.dn, container)
            logger.info("Group with dn {} created on active directory", adGroup.dn)
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