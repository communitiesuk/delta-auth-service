package uk.gov.communities.delta.auth.controllers.internal

import io.ktor.http.*
import io.ktor.server.application.*
import io.ktor.server.auth.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import kotlinx.serialization.Serializable
import org.slf4j.LoggerFactory
import uk.gov.communities.delta.auth.config.LDAPConfig
import uk.gov.communities.delta.auth.plugins.ApiError
import uk.gov.communities.delta.auth.repositories.isInternal
import uk.gov.communities.delta.auth.services.*

class EditAccessGroupsController(
    private val userLookupService: UserLookupService,
    private val groupService: GroupService,
    private val organisationService: OrganisationService,
    private val accessGroupsService: AccessGroupsService,
    private val memberOfToDeltaRolesMapperFactory: MemberOfToDeltaRolesMapperFactory,
    ) {

    private val logger = LoggerFactory.getLogger(javaClass)

    fun route(route: Route) {
        route.post { updateUserAccessGroups(call) }
    }

    // This endpoint takes a list of access groups to add and to remove in the form of maps of the group name (with
    // delta prefix) and a list of organisations for that access group. Generation of the correct lists is performed in
    // Delta.
    private suspend fun updateUserAccessGroups(call: ApplicationCall) {
        val session = call.principal<OAuthSession>()!!
        val callingUser = userLookupService.lookupUserByCn(session.userCn)
        logger.atInfo().log("Updating access groups for user ${session.userCn}")
        val userInternal = callingUser.isInternal()

        val accessGroupsRequestMap = call.receive<DeltaUserAccessGroups>().accessGroupsRequest
        val accessGroupsRequested = accessGroupsRequestMap.filter { m -> m.value.isNotEmpty() }

        val allAccessGroups = accessGroupsService.getAllAccessGroups()

        if (!allAccessGroups.all {
            ag -> !accessGroupsRequested.containsKey(LDAPConfig.DATAMART_DELTA_PREFIX + ag.name)
                    || (ag.enableOnlineRegistration && (!userInternal || ag.enableInternalUser))
        }) {
            logger.atError().log("Invalid access group assignment requested.")
            logger.atError().log("Access groups request from user ${session.userCn}: "
                    + accessGroupsRequested.toString())
            throw ApiError(
                HttpStatusCode.Forbidden,
                "illegal_role",
                "Attempted to assign a user an access group they are not permitted",
            )
        }

        val mapperResult = memberOfToDeltaRolesMapperFactory(
            callingUser.cn, organisationService.findAllNamesAndCodes(), accessGroupsService.getAllAccessGroups()
        ).map(callingUser.memberOfCNs)

        // if a user is not presented with the option to be a member of an access group, we do not alter their membership here.
        // the map sent from Delta contains all and only the access groups the user was given the option of being a member of.
        val currentAccessGroups = mapperResult.accessGroups.associateBy({LDAPConfig.DATAMART_DELTA_PREFIX + it.name}, {it.organisationIds})
            .filter { ag -> accessGroupsRequestMap.containsKey(ag.key)}

        val flatCurrentGroupsWithOrgs = unpackAccessGroupMap(currentAccessGroups)
        val flatRequestedGroupsWithOrgs = unpackAccessGroupMap(accessGroupsRequested)

        val groupsToAdd = flatRequestedGroupsWithOrgs.toSet().minus(flatCurrentGroupsWithOrgs.toSet())
        val groupsToRemove = flatCurrentGroupsWithOrgs.toSet().minus(flatRequestedGroupsWithOrgs.toSet())

        logger.atInfo().log("Adding user ${session.userCn} to access groups $groupsToAdd")
        groupsToAdd.forEach { g -> groupService.addUserToGroup(callingUser.cn, callingUser.dn, g, call, null)}

        logger.atInfo().log("Removing user ${session.userCn} from access groups $groupsToRemove")
        groupsToRemove.forEach { g -> groupService.removeUserFromGroup(callingUser.cn, callingUser.dn, g, call, null)}

        return call.respond(mapOf("message" to "Access groups have been updated. Any changes to your roles or access groups will take effect the next time you log in."))
    }

    private fun unpackAccessGroupMap(accessGroupMap: Map<String, List<String>>): List<String> =
        accessGroupMap.flatMap { i -> i.value.map { j -> i.key + "-" + j } } + accessGroupMap.map { i -> i.key }

    @Serializable
    data class DeltaUserAccessGroups(
        val accessGroupsRequest: Map<String, List<String>>,
    )
}
