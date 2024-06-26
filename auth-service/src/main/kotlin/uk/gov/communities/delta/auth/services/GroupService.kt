package uk.gov.communities.delta.auth.services

import io.ktor.server.application.*
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import org.slf4j.LoggerFactory
import uk.gov.communities.delta.auth.config.LDAPConfig
import uk.gov.communities.delta.auth.repositories.LdapUser
import java.util.*
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

    private suspend fun addGroupToAD(adGroup: ADGroup) {
        val container: Attributes = BasicAttributes()
        container.put(adGroup.objectClasses)
        container.put(BasicAttribute("cn", adGroup.cn))
        ldapServiceUserBind.useServiceUserBind {
            it.createSubcontext(adGroup.dn, container)
            logger.info("Group with dn {} created on active directory", adGroup.dn)
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
        user: LdapUser,
        groupCN: String,
        call: ApplicationCall,
        triggeringAdminSession: OAuthSession?,
    ) {
        val groupDN = ldapConfig.groupDnFormat.format(groupCN)

        if (!groupExists(groupDN)) {
            createGroup(groupCN)
        }
        ldapServiceUserBind.useServiceUserBind {
            val member = BasicAttribute("member", user.dn)
            val modificationItems = arrayOf(ModificationItem(DirContext.ADD_ATTRIBUTE, member))
            it.modifyAttributes(groupDN, modificationItems)
            logger.atInfo().addKeyValue("UserDN", user.dn).log("User added to group with dn {}", groupDN)
        }
        auditAddingUserToGroup(user.getGUID(), groupCN, triggeringAdminSession, call)
    }

    suspend fun removeUserFromGroup(
        user: LdapUser,
        groupCN: String,
        call: ApplicationCall,
        triggeringAdminSession: OAuthSession?,
    ) {
        val groupDN = ldapConfig.groupDnFormat.format(groupCN)

        ldapServiceUserBind.useServiceUserBind {
            val member = BasicAttribute("member", user.dn)
            val modificationItems = arrayOf(ModificationItem(DirContext.REMOVE_ATTRIBUTE, member))
            it.modifyAttributes(groupDN, modificationItems)
            logger.atInfo().addKeyValue("UserDN", user.dn).log("User removed from group with dn {}", groupDN)
        }
        auditRemovingUserFromGroup(user.getGUID(), groupCN, triggeringAdminSession, call)
    }

    private suspend fun auditAddingUserToGroup(
        userGUID: UUID,
        groupCN: String,
        triggeringAdminSession: OAuthSession?,
        call: ApplicationCall
    ) {
        val auditData = Json.encodeToString(AddedGroupAuditData(groupCN))
        if (triggeringAdminSession != null)
            userAuditService.userUpdateByAdminAudit(userGUID, triggeringAdminSession.userGUID, call, auditData)
        else
            userAuditService.userUpdateAudit(userGUID, call, auditData)
    }

    private suspend fun auditRemovingUserFromGroup(
        userGUID: UUID,
        groupCN: String,
        triggeringAdminSession: OAuthSession?,
        call: ApplicationCall
    ) {
        val auditData = Json.encodeToString(RemovedGroupAuditData(groupCN))
        if (triggeringAdminSession != null)
            userAuditService.userUpdateByAdminAudit(userGUID, triggeringAdminSession.userGUID, call, auditData)
        else
            userAuditService.userUpdateAudit(userGUID, call, auditData)
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
    private data class AddedGroupAuditData(val addedGroupCN: String)

    @Serializable
    private data class RemovedGroupAuditData(val removedGroupCN: String)
}
