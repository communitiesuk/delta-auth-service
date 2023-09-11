package uk.gov.communities.delta.auth.services

import org.slf4j.LoggerFactory
import uk.gov.communities.delta.auth.config.LDAPConfig
import uk.gov.communities.delta.auth.utils.ADUser
import javax.naming.directory.*

class NewUserService(
    private val ldapService: LdapService,
    private val ldapConfig: LDAPConfig,
) {

    private val logger = LoggerFactory.getLogger(javaClass)

    fun createUser(adUser: ADUser) {
        try {
            addUserToAD(adUser)
        } catch (e: Exception) {
            logger.error("Problem creating user {}", e.toString())
            throw e
        }
    }


    private fun addUserToAD(adUser: ADUser) {
        val context = ldapService.bind(
            ldapConfig.serviceUserDnFormat.format(ldapConfig.authServiceUserCn),
            ldapConfig.authServiceUserPassword,
            poolConnection = true
        )

        val container: Attributes = BasicAttributes()
        container.put(adUser.objClasses)
        container.put(BasicAttribute("userPrincipalName", adUser.userPrincipalName))
        container.put(BasicAttribute("cn", adUser.cn))
        container.put(BasicAttribute("sn", adUser.sn))
        container.put(BasicAttribute("givenName", adUser.givenName))
        container.put(BasicAttribute("mail", adUser.mail))
        container.put(BasicAttribute("st", adUser.st))
        container.put(BasicAttribute("userAccountControl", adUser.userAccountControl))

        try {
            context.createSubcontext(adUser.dn, container)
        } catch (e: Exception) {
            logger.error("Problem creating user: {}", e.toString())
            throw e
        }
    }

    fun addUserToGroup(adUser: ADUser, groupName: String) {
        val member = BasicAttribute("member", adUser.dn)
        val modificationItems = arrayOf(ModificationItem(DirContext.ADD_ATTRIBUTE, member))
        val context = ldapService.bind(
            ldapConfig.serviceUserDnFormat.format(ldapConfig.authServiceUserCn),
            ldapConfig.authServiceUserPassword,
            poolConnection = true
        )
        val groupDN = ldapConfig.groupDnFormat.format(groupName)
        context.modifyAttributes(groupDN, modificationItems)
    }
}