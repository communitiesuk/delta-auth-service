package uk.gov.communities.delta.auth.controllers.external

import io.ktor.http.*
import io.ktor.server.application.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import io.ktor.server.util.*
import org.slf4j.LoggerFactory
import uk.gov.communities.delta.auth.plugins.ApiError
import uk.gov.communities.delta.auth.security.IADLdapLoginService
import uk.gov.communities.delta.auth.services.DeltaApiTokenService

class ExternalDeltaApiTokenController(
    private val tokenService: DeltaApiTokenService,
    private val ldapService: IADLdapLoginService,
) {
    private val logger = LoggerFactory.getLogger(javaClass)

    fun route(route: Route) {
        route.post {
            createApiToken(call)
        }
    }

    suspend fun createApiToken(call: ApplicationCall) {
        val params = call.receiveParameters()
        val grant_type = params.getOrFail("grant_type")
        val username = params.getOrFail("username")
        val password = params.getOrFail("password")
        val clientId = params.getOrFail("client_id")
        val clientSecret = params.getOrFail("client_secret")

        logger.atInfo()
            .addKeyValue("userCn", username)
            .addKeyValue("clientId", clientId)
            .log("Received API token request")

        if (grant_type != "password") {
            throw ApiError(
                HttpStatusCode.BadRequest,
                "invalid_grant_type",
                "grant_type must be password",
            )
        }

        if (!tokenService.validateApiClientIdAndSecret(clientId, clientSecret)) {
            throw ApiError(
                HttpStatusCode.Unauthorized,
                "invalid_client",
                "client credentials not recognised",
            )
        }

        // we accept emails as well as CNs to match Keycloak
        val userCn = username.replace('@', '!')
        val loginResult = ldapService.ldapLogin(userCn, password)
        if (loginResult !is IADLdapLoginService.LdapLoginSuccess) {

            logger.atInfo()
                .addKeyValue("userCn", userCn)
                .addKeyValue("loginFailureType", loginResult.javaClass.simpleName)
                .log("Login failed")

            throw ApiError(
                HttpStatusCode.Unauthorized,
                "invalid_grant",
                "user credentials not recognised",
            )
        }

        val apiToken = tokenService.createAndStoreApiToken(userCn, clientId, loginResult.user.getGUID(), call)
        return call.respond(mapOf(
            "access_token" to apiToken,
            "expires_in" to (DeltaApiTokenService.API_TOKEN_EXPIRY_HOURS * 3600).toString(),
            "token_type" to "Bearer"
        ))
    }
}
