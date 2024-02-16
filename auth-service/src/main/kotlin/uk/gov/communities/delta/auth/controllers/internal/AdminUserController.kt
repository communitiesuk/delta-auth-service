package uk.gov.communities.delta.auth.controllers.internal

import io.ktor.http.*
import io.ktor.server.application.*
import io.ktor.server.auth.*
import org.slf4j.LoggerFactory
import uk.gov.communities.delta.auth.plugins.ApiError
import uk.gov.communities.delta.auth.services.OAuthSession
import uk.gov.communities.delta.auth.services.UserLookupService

open class AdminUserController(
    private val userLookupService: UserLookupService,
) {

    private val logger = LoggerFactory.getLogger(javaClass)

    protected suspend fun checkUserHasPermittedRole(
        permittedRoles: Array<String>,
        call: ApplicationCall
    ) {
        getSessionIfUserHasPermittedRole(permittedRoles, call)
    }

    protected suspend fun getSessionIfUserHasPermittedRole(
        permittedRoles: Array<String>,
        call: ApplicationCall
    ): OAuthSession {
        val session = call.principal<OAuthSession>()!!
        val callingUser = userLookupService.lookupUserByCn(session.userCn)

        // Authenticate calling user
        if (!callingUser.memberOfCNs.any { it in permittedRoles } || !callingUser.accountEnabled) {
            logger.atWarn().log("User does not have the necessary permissions to view/edit the user")
            throw ApiError(
                HttpStatusCode.Forbidden,
                "forbidden",
                "User is not an enabled admin",
                "You do not have the necessary permissions to do this"
            )
        }
        return session
    }
}