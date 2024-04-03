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
import uk.gov.communities.delta.auth.services.GroupService
import uk.gov.communities.delta.auth.services.OAuthSession
import uk.gov.communities.delta.auth.services.OrganisationService
import uk.gov.communities.delta.auth.services.UserLookupService

class EditOrganisationsController(
    private val userLookupService: UserLookupService,
    private val groupService: GroupService,
    private val organisationService: OrganisationService,
) {

    private val logger = LoggerFactory.getLogger(javaClass)

    fun route(route: Route) {
        route.post { updateUserOrganisations(call) }
    }

    // This endpoint takes a list of organisation codes which should contain all and only the domain organisations of which
    // the user should be a member after the execution of the endpoint. Note that if the user is a member of any organisations
    // not in their domain, these will NOT be affected by this endpoint.
    private suspend fun updateUserOrganisations(call: ApplicationCall) {
        val session = call.principal<OAuthSession>()!!
        val callingUser = userLookupService.lookupUserByCNAndLoadRoles(session.userCn)
        logger.atInfo().log("Updating organisations for user {}", session.userCn)

        val requestedOrganisations = call.receive<DeltaUserOrganisations>().selectedDomainOrganisationCodes
        val userDomainOrgs =
            if (callingUser.user.email == null) setOf() else organisationService.findAllByDomain(callingUser.user.email)
                .associateBy { it.code }.keys

        val allUserOrgs = callingUser.roles.organisations.map { it.code }.toSet()

        val userNonDomainOrgs = allUserOrgs.minus(userDomainOrgs)
        validateOrganisationRequest(requestedOrganisations, userDomainOrgs, userNonDomainOrgs)

        val userRoles = callingUser.roles.systemRoles
        val existingDomainOrganisations =
            callingUser.roles.organisations.map { it.code }.toSet().intersect(userDomainOrgs)

        val orgsToAdd = requestedOrganisations.toSet().minus(existingDomainOrganisations.toSet())
        val orgsToRemove = existingDomainOrganisations.toSet().minus(requestedOrganisations.toSet())

        for (org in orgsToAdd) {
            for (role in userRoles) {
                val roleGroupString = role.role.adCn(org)
                groupService.addUserToGroup(callingUser.user.cn, callingUser.user.dn, roleGroupString, call, null)
            }
        }

        for (org in orgsToRemove) {
            for (group in callingUser.user.memberOfCNs) {
                if (group.endsWith("-$org")) {
                    groupService.removeUserFromGroup(
                        callingUser.user.cn,
                        callingUser.user.dn,
                        group,
                        call,
                        null
                    )
                }
            }
        }

        return call.respond(mapOf("message" to "Organisations have been updated. Any changes to your roles or access groups will take effect the next time you log in."))
    }

    fun validateOrganisationRequest(
        requestedOrganisations: List<String>,
        userDomainOrgs: Set<String>,
        userNonDomainOrgs: Set<String>
    ) {
        if (requestedOrganisations.isEmpty() && userNonDomainOrgs.isEmpty()) {
            throw ApiError(
                HttpStatusCode.Forbidden,
                "zero_organisations",
                "User attempted to remove last organisation"
            )
        }
        for (org in requestedOrganisations) {
            if (!userDomainOrgs.contains(org)) {
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
        val selectedDomainOrganisationCodes: List<String>,
    )
}
