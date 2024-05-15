package uk.gov.communities.delta.auth.controllers.external

import io.ktor.http.*
import io.ktor.server.application.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
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
        val requestPayload = call.receive<ApiTokenRequest>()

        if (requestPayload.grant_type != "password") {
            throw ApiError(
                HttpStatusCode.Forbidden,
                "invalid_grant_type",
                "grant_type must be password",
            )
        }

        // TODO 836 check this takes a CN rather than an email (if it takes an email, rename things to match)
        // TODO 836 also check whether keycloak takes an email
        val loginResult = ldapService.ldapLogin(requestPayload.username, requestPayload.password)

        if (loginResult !is IADLdapLoginService.LdapLoginSuccess ||
            !tokenService.validateApiClientIdAndSecret(requestPayload.client_id, requestPayload.client_secret)) {
            throw ApiError(
                HttpStatusCode.Forbidden,
                "invalid_credentials",
                "user or client credentials not recognised",
            )
        }

        val apiToken = tokenService.createAndStoreApiToken(requestPayload.username, requestPayload.client_id)
        return call.respond(mapOf(
            "access_token" to apiToken,
            "expires_in" to (DeltaApiTokenService.API_TOKEN_EXPIRY_HOURS * 3600).toString(),
            "token_type" to "Bearer"
        ))
    }

    @Serializable
    data class ApiTokenRequest(
        @SerialName("grant_type") val grant_type: String,
        @SerialName("username") val username: String,
        @SerialName("password") val password: String,
        @SerialName("client_id") val client_id: String,
        @SerialName("client_secret") val client_secret: String,
    )
}
