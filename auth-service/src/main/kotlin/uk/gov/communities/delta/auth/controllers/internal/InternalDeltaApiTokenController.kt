package uk.gov.communities.delta.auth.controllers.internal

import io.ktor.server.application.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import kotlinx.serialization.Serializable
import org.slf4j.LoggerFactory
import uk.gov.communities.delta.auth.services.DeltaApiTokenService

class InternalDeltaApiTokenController(
    private val tokenService: DeltaApiTokenService
) {

    private val logger = LoggerFactory.getLogger(javaClass)

    suspend fun validateApiRequest(call: ApplicationCall) {
        // TODO 836 any validation or whatever here?

        val apiToken = call.receive<ApiValidationRequest>().token

        if (tokenService.validateApiToken(apiToken)) {
            val samlToken = tokenService.generateApiSamlToken()
            return call.respond(mapOf("saml_token" to samlToken))
        }
    }

    @Serializable
    data class ApiValidationRequest(
        val token: String,
    )
}
