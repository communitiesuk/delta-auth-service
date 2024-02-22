package uk.gov.communities.delta.auth.controllers.internal

import io.ktor.http.*
import io.ktor.server.application.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.serialization.Serializable
import org.slf4j.LoggerFactory
import uk.gov.communities.delta.auth.config.DeltaConfig
import uk.gov.communities.delta.auth.repositories.LdapUser
import uk.gov.communities.delta.auth.services.*
import javax.naming.NameNotFoundException

class AdminGetUserController(
    private val userLookupService: UserLookupService,
    private val organisationService: OrganisationService,
    private val accessGroupsService: AccessGroupsService,
    private val memberOfToDeltaRolesMapperFactory: MemberOfToDeltaRolesMapperFactory,
) : AdminUserController(userLookupService) {

    private val logger = LoggerFactory.getLogger(javaClass)

    fun route(route: Route) {
        route.get { getUser(call) }
    }

    private suspend fun getUser(call: ApplicationCall) {
        getSessionIfUserHasPermittedRole(
            arrayOf(
                DeltaConfig.DATAMART_DELTA_ADMIN,
                DeltaConfig.DATAMART_DELTA_READ_ONLY_ADMIN,
            ), call
        )

        val cn = call.request.queryParameters["userCn"]!!
        logger.atInfo().log("Getting info for user $cn")
        val user: LdapUser
        try {
            user = userLookupService.lookupUserByCn(cn)
        } catch (e: NameNotFoundException) {
            return call.respond(HttpStatusCode.NotFound, "User not found")
        }
        coroutineScope {
            val allOrganisations = async { organisationService.findAllNamesAndCodes() }
            val allAccessGroups = async { accessGroupsService.getAllAccessGroups() }

            val roles = memberOfToDeltaRolesMapperFactory(
                user.cn, allOrganisations.await(), allAccessGroups.await()
            ).map(user.memberOfCNs)
            call.respond(UserWithRoles(user, roles))
        }

    }

    @Serializable
    data class UserWithRoles(val user: LdapUser, val roles: MemberOfToDeltaRolesMapper.Roles)
}