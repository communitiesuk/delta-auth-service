package uk.gov.communities.delta.auth.controllers.internal

import io.ktor.http.HttpStatusCode
import io.ktor.server.application.ApplicationCall
import io.ktor.server.response.respond
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import org.slf4j.LoggerFactory
import uk.gov.communities.delta.auth.plugins.ApiError
import uk.gov.communities.delta.auth.repositories.LdapRepository
import uk.gov.communities.delta.auth.services.AccessGroupsService


class AccessGroupMembersController (
    private val ldapRepository: LdapRepository,
    private val accessGroupsService: AccessGroupsService,
) {

    private val logger = LoggerFactory.getLogger(javaClass)

    // This endpoint takes a single access group and organisation id and retrieves the members and their roles of that AD group.
    suspend fun getAccessGroupMembers(call: ApplicationCall) {
        val accessGroupName = call.request.queryParameters["accessGroupName"]
        val organisationId = call.request.queryParameters["organisationId"]

        validateRequestFields(accessGroupName, organisationId)
        accessGroupName?.let { validateAccessGroupName(it) }

        try {
            val accessGroupMembers = ldapRepository.getUsersForOrgAccessGroupWithRoles(accessGroupName.toString(),
                organisationId.toString()
            )
            call.respond(HttpStatusCode.OK, accessGroupMembers)
        }  catch (e: Exception) {
            logger.error("Failed to retrieve group members due to: ${e.localizedMessage}")
            throw ApiError(HttpStatusCode.InternalServerError,
                "internal_error",
                e.localizedMessage)
        }
    }

    fun validateRequestFields(accessGroupName: String?, organisationId: String?) {
        val missingFieldError: Pair<String, String>? = when {
            accessGroupName.isNullOrEmpty() -> Pair("no_access_group_name", "Access group name is missing in request")
            organisationId.isNullOrEmpty() -> Pair("no_organisation_id", "Organisation ID is missing in request")
            else -> null
        }

        missingFieldError?.let {
            throw ApiError(HttpStatusCode.BadRequest, it.first, it.second)
        }
    }

    fun validateAccessGroupName(accessGroupName: String) {
        try {
            accessGroupsService.checkAccessGroupNameIsValid(accessGroupName)
        } catch (e: IllegalArgumentException) {
            throw ApiError(HttpStatusCode.BadRequest, "invalid_access_group_name", {e.message}.toString())
        }

        try {
            accessGroupsService.checkAccessGroupPrefixIsValid(accessGroupName)
        } catch (e: IllegalArgumentException) {
            throw ApiError(HttpStatusCode.BadRequest, "invalid_access_group_name_prefix", {e.message}.toString())
        }
    }
}
