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

class EditOrganisationsController(
    private val userLookupService: UserLookupService,
    private val groupService: GroupService,
    private val organisationService: OrganisationService,
    private val accessGroupsService: AccessGroupsService,
    private val memberOfToDeltaRolesMapperFactory: MemberOfToDeltaRolesMapperFactory,
) {

    private val logger = LoggerFactory.getLogger(javaClass)

    fun route(route: Route) {
        route.post { updateUserOrganisations(call) }
    }

    // This endpoint takes a list of organisation codes which should contain all and only the organisations of which
    // the user should be a member after the execution of the endpoint
    private suspend fun updateUserOrganisations(call: ApplicationCall) {
        val session = call.principal<OAuthSession>()!!
        val callingUser = userLookupService.lookupUserByCn(session.userCn)
        logger.atInfo().log("Updating organisations for user {}", session.userCn)

        val requestedOrganisations = call.receive<DeltaUserOrganisations>().userSelectedOrgs
        val userDomainOrgs =
            if (callingUser.email == null) mapOf() else organisationService.findAllByDomain(callingUser.email)
                .associateBy { it.code }
        validateOrganisationRequest(requestedOrganisations, userDomainOrgs)

        val existingOrganisations = getExistingOrganisationsForUser(callingUser)

        val orgsToAdd = requestedOrganisations.toSet().minus(existingOrganisations.toSet())
        val orgsToRemove = existingOrganisations.toSet().minus(requestedOrganisations.toSet())

        val userRoles = memberOfToDeltaRolesMapperFactory(
            callingUser.cn, organisationService.findAllNamesAndCodes(), accessGroupsService.getAllAccessGroups()
        ).map(callingUser.memberOfCNs).systemRoles

        for (org in orgsToAdd) {
            for (role in userRoles) {
                val roleGroupString = role.role.adCn(org)
                groupService.addUserToGroup(callingUser.cn, callingUser.dn, roleGroupString, call, null)
            }
        }

        for (org in orgsToRemove) {
            for (group in callingUser.memberOfCNs) {
                if (group.endsWith(org)) {
                    groupService.removeUserFromGroup(
                        callingUser.cn,
                        callingUser.dn,
                        group,
                        call,
                        null
                    )
                }
            }
        }

        return call.respond(mapOf("message" to "Organisations have been updated. Any changes to your roles or access groups will take effect the next time you log in."))
    }

    private fun getExistingOrganisationsForUser(callingUser: LdapUser) = callingUser.memberOfCNs
        .filter { it.startsWith(DeltaConfig.DATAMART_DELTA_USER) }
        .map { it.removePrefix(DeltaConfig.DATAMART_DELTA_USER) }
        .filter { it.isNotEmpty() }
        .map { it.removePrefix("-") }

    private fun validateOrganisationRequest(
        requestedOrganisations: List<String>,
        userDomainOrgs: Map<String, Organisation>
    ) {
        if (requestedOrganisations.isEmpty()) {
            throw ApiError(
                HttpStatusCode.Forbidden,
                "zero_organisations",
                "User attempted to remove last organisation"
            )
        }
        for (org in requestedOrganisations) {
            if (!userDomainOrgs.containsKey(org)) {
                throw ApiError(
                    HttpStatusCode.Forbidden,
                    "non_domain_organisation",
                    "User attempted to assign self non-domain organisation: $org"
                )
            }
        }
    }

    @Serializable
    data class DeltaUserOrganisations(
        val userSelectedOrgs: List<String>,
    )
}
