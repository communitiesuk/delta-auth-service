package uk.gov.communities.delta.auth.services

import org.slf4j.LoggerFactory
import uk.gov.communities.delta.auth.config.LDAPConfig
import uk.gov.communities.delta.auth.utils.ADUser
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
            logger.error("Problem creating user {}", e.toString())
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
                logger.error("Problem creating user: {}", e.toString())
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
}