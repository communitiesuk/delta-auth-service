package uk.gov.communities.delta.auth.controllers.internal

import io.ktor.http.*
import io.ktor.server.application.*
import io.ktor.server.auth.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import kotlinx.serialization.Serializable
import org.slf4j.LoggerFactory
import uk.gov.communities.delta.auth.plugins.ApiError
import uk.gov.communities.delta.auth.repositories.isInternal
import uk.gov.communities.delta.auth.services.*

class EditRolesController(
    private val userLookupService: UserLookupService,
    private val groupService: GroupService,
    private val organisationService: OrganisationService,
    private val accessGroupsService: AccessGroupsService,
    private val memberOfToDeltaRolesMapperFactory: MemberOfToDeltaRolesMapperFactory,
    ) {

    private val logger = LoggerFactory.getLogger(javaClass)

    fun route(route: Route) {
        route.post { updateUserRoles(call) }
    }

    // This endpoint takes a list of roles and adds the user to any roles in the list they have permission to add
    // themselves to and are not already members of, while removing them from any roles they have permission to add
    // themselves to but did not include in the list
    private suspend fun updateUserRoles(call: ApplicationCall) {
        val session = call.principal<OAuthSession>()!!
        val callingUser = userLookupService.lookupUserByCn(session.userCn)
        logger.atInfo().log("Updating roles for user ${session.userCn}")
        val userInternal = callingUser.isInternal()

        val requestedRoles = call.receive<DeltaUserRoles>().roles.map { reqRoleStr ->
            DeltaSystemRole.entries.find { it.adRoleName == reqRoleStr }
                ?: throw ApiError(HttpStatusCode.BadRequest, "bad_request", "Unknown role $reqRoleStr")
        }

        val allowedClassifications = listOf(
            DeltaSystemRoleClassification.EXTERNAL_AUDIT,
            DeltaSystemRoleClassification.EXTERNAL,
        ) + if (userInternal) listOf(DeltaSystemRoleClassification.INTERNAL) else emptyList()

        val allowedRoles = DeltaSystemRole.entries.filter { allowedClassifications.contains(it.classification) }
        val allowedRoleNames = allowedRoles.map { it.adRoleName }

        if (!allowedRoles.containsAll(requestedRoles)) {
            logger.atError().log("External user attempted to give self internal-only role")
            throw ApiError(
                HttpStatusCode.Forbidden,
                "illegal_role",
                "Attempted to assign a user a role they are not permitted",
            )
        }

        val mapperResult = memberOfToDeltaRolesMapperFactory(
            callingUser.cn, organisationService.findAllNamesAndCodes(), accessGroupsService.getAllAccessGroups()
        ).map(callingUser.memberOfCNs)
        val systemRoles = mapperResult.systemRoles.filter { allowedRoleNames.contains(it.role.adRoleName) }
        val userOrgs = mapperResult.organisations

        val rolesToAdd = requestedRoles.map { it }.toSet().minus(systemRoles.map { it.role }.toSet())
        val groupCNsToAdd = rolesToAdd.flatMap { role -> userOrgs.map { org -> role.adCn(org.code) } } +
                rolesToAdd.map { it.adCn() }
        logger.atInfo().log("Granting user ${session.userCn} roles $groupCNsToAdd")

        groupCNsToAdd
            .forEach {
                groupService.addUserToGroup(callingUser.cn, callingUser.dn, it, call, null)
            }

        val rolesToRemove = systemRoles.map { it.role }.toSet().minus(requestedRoles.toSet())
        val groupCNsToRemove =
            rolesToRemove.flatMap { role -> userOrgs.map { org -> role.adCn(org.code) } } +
                    rolesToRemove.map { it.adCn() }
        val groupCNsToRemoveFilteredForMembership = groupCNsToRemove.filter { callingUser.memberOfCNs.contains(it) }
        logger.atInfo().log("Revoking user ${session.userCn} roles $groupCNsToRemoveFilteredForMembership")

        groupCNsToRemoveFilteredForMembership
            .forEach {
                groupService.removeUserFromGroup(callingUser.cn, callingUser.dn, it, call, null)
            }

        return call.respond(mapOf("message" to "Roles have been updated. Any changes to your roles or access groups will take effect the next time you log in."))
    }

    @Serializable
    data class DeltaUserRoles(
        val roles: List<String>,
    )
}
