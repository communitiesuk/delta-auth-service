package uk.gov.communities.delta.auth.services

import io.ktor.server.application.*
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import org.slf4j.LoggerFactory
import uk.gov.communities.delta.auth.config.LDAPConfig
import javax.naming.NameNotFoundException
import javax.naming.directory.*

class GroupService(
    private val ldapServiceUserBind: LdapServiceUserBind,
    private val ldapConfig: LDAPConfig,
    private val userAuditService: UserAuditService,
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
        return try {
            val attributes = ldapServiceUserBind.useServiceUserBind {
                it.getAttributes(
                    groupDn,
                    arrayOf("cn")
                )
            }
            attributes.get("cn") != null
        } catch (e: NameNotFoundException) {
            false
        }
    }

    suspend fun addUserToGroup(
        adUser: UserService.ADUser,
        groupCN: String,
        call: ApplicationCall,
        triggeringAdminSession: OAuthSession? = null,
    ) {
        val groupDN = ldapConfig.groupDnFormat.format(groupCN)

        if (!groupExists(groupDN)) {
            createGroup(groupCN)
        }
        ldapServiceUserBind.useServiceUserBind {
            val member = BasicAttribute("member", adUser.dn)
            val modificationItems = arrayOf(ModificationItem(DirContext.ADD_ATTRIBUTE, member))
            it.modifyAttributes(groupDN, modificationItems)
            logger.atInfo().addKeyValue("UserDN", adUser.dn).log("User added to group with dn {}", groupDN)
        }
        auditAddingUserToGroup(adUser.cn, groupCN, triggeringAdminSession, call)
    }

    private suspend fun auditAddingUserToGroup(userCN :String, groupCN: String, triggeringAdminSession: OAuthSession?, call: ApplicationCall) {
        val auditData = Json.encodeToString(GroupAuditData(groupCN))
        if (triggeringAdminSession != null)
            userAuditService.userUpdateByAdminAudit(userCN, triggeringAdminSession.userCn, call, auditData)
        else
            userAuditService.userUpdateAudit(userCN, call)
    }

    private suspend fun addGroupToAD(adGroup: ADGroup) {
        val container: Attributes = BasicAttributes()
        container.put(adGroup.objectClasses)
        container.put(BasicAttribute("cn", adGroup.cn))
        ldapServiceUserBind.useServiceUserBind {
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

    @Serializable
    private data class GroupAuditData(val groupCN: String)
}
