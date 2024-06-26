package uk.gov.communities.delta.auth.controllers.internal

import io.ktor.http.*
import io.ktor.server.application.*
import io.ktor.server.auth.*
import io.ktor.server.util.*
import org.slf4j.LoggerFactory
import uk.gov.communities.delta.auth.config.DeltaConfig
import uk.gov.communities.delta.auth.config.LDAPConfig
import uk.gov.communities.delta.auth.plugins.ApiError
import uk.gov.communities.delta.auth.security.DELTA_AD_LDAP_SERVICE_USERS_AUTH_NAME
import uk.gov.communities.delta.auth.security.DeltaLdapPrincipal
import uk.gov.communities.delta.auth.services.*
import uk.gov.communities.delta.auth.utils.getUserFromCallParameters
import javax.naming.NameAlreadyBoundException

class EditLdapGroupsController(
    private val groupService: GroupService,
    private val userLookupService: UserLookupService,
    private val userGUIDMapService: UserGUIDMapService,
) {
    private val logger = LoggerFactory.getLogger(javaClass)

    suspend fun addUserToGroup(call: ApplicationCall) {
        validateAuthorisation(call)
        val groupName = call.parameters.getOrFail("groupName")
        val groupCn = if (groupName.startsWith(LDAPConfig.DATAMART_DELTA_PREFIX)) groupName else LDAPConfig.DATAMART_DELTA_PREFIX + groupName

        val user = getUserFromCallParameters(
            call.parameters,
            userLookupService,
            userGUIDMapService,
            "An error occurred adding groups to the user",
            "add_ldap_group"
        )

        if (!user.memberOfCNs.contains(groupCn)) {
            logger.info("Adding user {} to group CN={}", user.getGUID(), groupCn)
            try {
                groupService.addUserToGroup(user, groupCn, call, null)
            } catch (e: NameAlreadyBoundException) {
                logger.warn("NameAlreadyBoundException trying to add user {} to group CN={}. Ignoring error.", user.getGUID(), groupCn)
            }
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
}
