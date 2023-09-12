package uk.gov.communities.delta.auth.services

import org.slf4j.LoggerFactory
import uk.gov.communities.delta.auth.config.LDAPConfig
import uk.gov.communities.delta.auth.utils.ADGroup
import javax.naming.directory.Attributes
import javax.naming.directory.BasicAttribute
import javax.naming.directory.BasicAttributes

class GroupService(
    private val ldapService: LdapService,
    private val ldapConfig: LDAPConfig,
) {

    private val logger = LoggerFactory.getLogger(javaClass)

    fun createGroup(groupName: String) {
        try {
            addGroupToAD(ADGroup(groupName, ldapConfig))
        } catch (e: Exception) {
            logger.error("Problem creating user {}", e.toString())
            throw e
        }
    }

    private fun addGroupToAD(adGroup: ADGroup) {
        val context = ldapService.bind(
            ldapConfig.serviceUserDnFormat.format(ldapConfig.authServiceUserCn),
            ldapConfig.authServiceUserPassword,
            poolConnection = true
        )

        val container: Attributes = BasicAttributes()
        container.put(adGroup.objectClasses)
        container.put(BasicAttribute("cn", adGroup.cn))

        try {
            context.createSubcontext(adGroup.dn, container)
        } catch (e: Exception) {
            logger.error("Problem creating group: {}", e.toString())
            throw e
        }
    }
}