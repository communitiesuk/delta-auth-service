package uk.gov.communities.delta.auth.controllers.internal

import io.ktor.http.*
import io.ktor.server.application.*
import io.ktor.server.auth.*
import org.slf4j.LoggerFactory
import uk.gov.communities.delta.auth.plugins.ApiError
import uk.gov.communities.delta.auth.repositories.LdapUser
import uk.gov.communities.delta.auth.services.DeltaSystemRole
import uk.gov.communities.delta.auth.services.OAuthSession
import uk.gov.communities.delta.auth.services.UserLookupService

open class AdminUserController(
    private val userLookupService: UserLookupService,
) {

    private val logger = LoggerFactory.getLogger(javaClass)

    protected suspend fun checkUserHasPermittedRole(
        permittedRoles: Array<DeltaSystemRole>,
        call: ApplicationCall
    ) {
        getSessionIfUserHasPermittedRole(permittedRoles, call)
    }

    protected suspend fun getSessionAndUserIfUserHasPermittedRole(
        permittedRoles: Array<DeltaSystemRole>,
        call: ApplicationCall
    ): Pair<OAuthSession, LdapUser> {
        val session = call.principal<OAuthSession>()!!
        val callingUser = userLookupService.lookupCurrentUser(session)
        val roleCns = permittedRoles.map { it.adCn() }

        // Authenticate calling user
        if (!callingUser.memberOfCNs.any { it in roleCns } || !callingUser.accountEnabled) {
            logger.atWarn().log("User does not have the necessary permissions to view/edit the user")
            throw ApiError(
                HttpStatusCode.Forbidden,
                "forbidden",
                "User is not an enabled admin",
                "You do not have the necessary permissions to do this"
            )
        }
        return Pair(session, callingUser)
    }

    protected suspend fun getSessionIfUserHasPermittedRole(
        permittedRoles: Array<DeltaSystemRole>,
        call: ApplicationCall
    ): OAuthSession {
        return getSessionAndUserIfUserHasPermittedRole(permittedRoles, call).first
    }
}
