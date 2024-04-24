package uk.gov.communities.delta.auth.controllers.internal

import io.ktor.http.*
import io.ktor.server.application.*
import io.ktor.server.auth.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import kotlinx.serialization.Serializable
import org.slf4j.LoggerFactory
import uk.gov.communities.delta.auth.config.DeltaConfig
import uk.gov.communities.delta.auth.plugins.ApiError
import uk.gov.communities.delta.auth.repositories.LdapUser
import uk.gov.communities.delta.auth.services.*

class EditRolesController(
    private val userLookupService: UserLookupService,
    private val groupService: GroupService,
    ) {

    private val logger = LoggerFactory.getLogger(javaClass)

    fun route(route: Route) {
        route.post { updateUserRoles(call) }
    }

    // This endpoint takes a list of roles to add and remove
    // The user must have permission to add/remove themselves from the roles
    // Trying to add a role the user already has, or remove one they don't, has no effect
    private suspend fun updateUserRoles(call: ApplicationCall) {
        val session = call.principal<OAuthSession>()!!
        val request = call.receive<DeltaUserRolesRequest>()

        val (callingUser, callingUserRoles) = userLookupService.lookupUserByCNAndLoadRoles(session.userCn)
        logger.atInfo().log("Request to update own roles for user ${session.userCn}")

        checkRequestedRolesArePermitted(request, callingUser)

        val userSystemRoles = callingUserRoles.systemRoles
        val userOrganisations = callingUserRoles.organisations

        val rolesToAdd = request.addToRoles.toSet().minus(userSystemRoles.map { it.role }.toSet())
        val groupCNsToAdd = rolesToAdd.flatMap { role -> userOrganisations.map { org -> role.adCn(org.code) } } +
                rolesToAdd.map { it.adCn() }
        val groupCNsToAddFilteredForNonMembership = groupCNsToAdd.filter { !callingUser.memberOfCNs.contains(it) }

        val rolesToRemove = request.removeFromRoles
        val groupCNsToRemove = rolesToRemove.flatMap { role -> userOrganisations.map { org -> role.adCn(org.code) } } +
                rolesToRemove.map { it.adCn() }
        val groupCNsToRemoveFilteredForMembership =
            groupCNsToRemove.filter { callingUser.memberOfCNs.contains(it) }

        logger.atInfo().log("Granting user ${session.userCn} groups $groupCNsToAddFilteredForNonMembership")
        groupCNsToAddFilteredForNonMembership
            .forEach {
                groupService.addUserToGroup(callingUser.cn, callingUser.getUUID(), callingUser.dn, it, call, null)
            }

        logger.atInfo().log("Revoking user ${session.userCn} groups $groupCNsToRemoveFilteredForMembership")
        groupCNsToRemoveFilteredForMembership
            .forEach {
                groupService.removeUserFromGroup(callingUser.cn, callingUser.getUUID(), callingUser.dn, it, call, null)
            }

        return call.respond(mapOf("message" to "Roles have been updated. Any changes to your roles or access groups will take effect the next time you log in."))
    }

    private fun checkRequestedRolesArePermitted(request: DeltaUserRolesRequest, callingUser: LdapUser) {
        val userIsInternal = callingUser.isInternal()
        val allowedRoles = allowedRoles(userIsInternal)

        request.addToRoles.firstOrNull { !allowedRoles.contains(it) }?.let {
            logger.atError().log("User not permitted to add self to role {} (internal: {})", it.adRoleName, userIsInternal)
            throw ApiError(
                HttpStatusCode.Forbidden,
                "illegal_role",
                "Not permitted to add role ${it.adRoleName}",
            )
        }
        request.removeFromRoles.firstOrNull { !allowedRoles.contains(it) }?.let {
            logger.atError()
                .log("User not permitted to remove self from role {} (internal: {})", it.adRoleName, userIsInternal)
            throw ApiError(
                HttpStatusCode.Forbidden,
                "illegal_role",
                "Not permitted to remove role ${it.adRoleName}",
            )
        }
    }

    private fun allowedRoles(userIsInternal: Boolean): List<DeltaSystemRole> {
        val allowedClassifications = listOf(
            DeltaSystemRoleClassification.EXTERNAL_AUDIT,
            DeltaSystemRoleClassification.EXTERNAL,
        ) + if (userIsInternal) listOf(DeltaSystemRoleClassification.INTERNAL) else emptyList()

        return DeltaSystemRole.entries.filter { allowedClassifications.contains(it.classification) }
    }

    private fun LdapUser.isInternal() : Boolean {
        return this.memberOfCNs.contains(DeltaConfig.DATAMART_DELTA_INTERNAL_USER)
    }

    @Serializable
    data class DeltaUserRolesRequest(
        val addToRoles: Set<DeltaSystemRole>,
        val removeFromRoles: Set<DeltaSystemRole>,
    )
}
