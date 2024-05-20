package uk.gov.communities.delta.auth.controllers.internal

import io.ktor.http.*
import io.ktor.server.application.*
import io.ktor.server.auth.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import org.slf4j.LoggerFactory
import uk.gov.communities.delta.auth.config.DeltaConfig
import uk.gov.communities.delta.auth.config.LDAPConfig
import uk.gov.communities.delta.auth.plugins.ApiError
import uk.gov.communities.delta.auth.plugins.HttpNotFound404PageException
import uk.gov.communities.delta.auth.repositories.LdapUser
import uk.gov.communities.delta.auth.repositories.isInternal
import uk.gov.communities.delta.auth.security.DELTA_AD_LDAP_SERVICE_USERS_AUTH_NAME
import uk.gov.communities.delta.auth.security.DeltaLdapPrincipal
import uk.gov.communities.delta.auth.services.*

class EditLdapGroupsController(
    private val groupService: GroupService,
    private val userLookupService: UserLookupService
) {
    private val logger = LoggerFactory.getLogger(javaClass)

    suspend fun createLdapGroupIfNotExists(call: ApplicationCall) {
        validateAuthorisation(call)
        val groupName = getParamOrThrow(call, "groupName")
        
        if (groupService.groupExists(groupName)) {
            call.response.status(HttpStatusCode.NoContent)
        } else {
            val groupCn = LDAPConfig.DATAMART_DELTA_PREFIX + groupName
            logger.info("Creating missing LDAP group, CN={}", groupCn)
            groupService.createGroup(groupCn)
            call.response.status(HttpStatusCode.Created)
        }
    }

    suspend fun addUserToGroup(call: ApplicationCall) {
        validateAuthorisation(call)
        val groupName = getParamOrThrow(call, "groupName")
        val groupCn = LDAPConfig.DATAMART_DELTA_PREFIX + groupName
        
        val userCn = getParamOrThrow(call, "userCn")
        val user = userLookupService.lookupUserByCn(userCn)
        
        if (!user.memberOfCNs.contains(groupCn)) {
            logger.info("Adding User CN={} to group CN={}", userCn, groupCn)
            groupService.addUserToGroup(user.cn, user.dn, groupCn, call, null)
        }
        call.response.status(HttpStatusCode.NoContent)
    }

    suspend fun removeUserFromGroup(call: ApplicationCall) {
        validateAuthorisation(call)
        val groupName = getParamOrThrow(call, "groupName")
        val groupCn = LDAPConfig.DATAMART_DELTA_PREFIX + groupName

        val userCn = getParamOrThrow(call, "userCn")
        val user = userLookupService.lookupUserByCn(userCn)

        if (user.memberOfCNs.contains(groupCn)) {
            logger.info("Removing User CN={} from group CN={}", userCn, groupCn)
            groupService.removeUserFromGroup(user.cn, user.dn, groupCn, call, null)
        }
        call.response.status(HttpStatusCode.NoContent)
    }
    
    private fun validateAuthorisation(call: ApplicationCall) {
        val callingUser = call.principal<DeltaLdapPrincipal>(DELTA_AD_LDAP_SERVICE_USERS_AUTH_NAME)!!
        if (!callingUser.ldapUser.memberOfCNs.contains(DeltaConfig.DATAMART_DELTA_MARKLOGIC_ADMIN)) {
            throw ApiError(
                HttpStatusCode.Forbidden,
                "forbidden",
                "User is not the Delta App service user",
                "You do not have the necessary permissions to do this"
            )
        }
    }

    private fun getParamOrThrow(call: ApplicationCall, paramName: String): String {
        if (!call.parameters.contains(paramName)) {
            throw ApiError(
                HttpStatusCode.BadRequest,
                "missing_parameter",
                "Missing parameter $paramName",
                "Missing parameter $paramName"
            )
        }
        return call.parameters["groupName"]!!
    }
}
