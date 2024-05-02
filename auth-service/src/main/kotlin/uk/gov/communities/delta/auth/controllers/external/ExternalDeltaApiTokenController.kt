package uk.gov.communities.delta.auth.controllers.external

import io.ktor.http.*
import io.ktor.server.application.*
import io.ktor.server.request.*
import io.ktor.server.response.*
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

    suspend fun createApiToken(call: ApplicationCall) {
        val requestPayload = call.receive<ApiTokenRequest>()

        // TODO 836 do we need to do something fancier like in the logincontroller?
        val loginResult = ldapService.ldapLogin(requestPayload.username, requestPayload.password)

        if (loginResult !is IADLdapLoginService.LdapLoginSuccess ||
            !tokenService.validateApiClientIdAndSecret(requestPayload.client_id, requestPayload.client_secret)) {
            throw ApiError(
                HttpStatusCode.Forbidden,
                "invalid credentials",
                "user or client credentials not recognised",
            )
        }

        val apiToken = tokenService.createAndStoreApiToken(requestPayload.username, requestPayload.client_id)
        return call.respond(mapOf("api_token" to apiToken))
    }

    @Serializable
    data class ApiTokenRequest(
        val username: String,
        val password: String,
        val client_id: String,
        val client_secret: String,
    )
}
