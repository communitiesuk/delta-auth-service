package uk.gov.communities.delta.auth.controllers.external

import io.ktor.server.application.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import kotlinx.serialization.Serializable
import org.slf4j.LoggerFactory
import uk.gov.communities.delta.auth.services.DeltaApiTokenService

class ExternalDeltaApiTokenController(
    private val tokenService: DeltaApiTokenService
) {

    private val logger = LoggerFactory.getLogger(javaClass)

    suspend fun createApiToken(call: ApplicationCall) {
        val requestPayload = call.receive<ApiTokenRequest>()

        val apiToken = tokenService.generateApiSamlToken()
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
