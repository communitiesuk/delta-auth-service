package uk.gov.communities.delta.auth.controllers.internal

import io.ktor.http.*
import io.ktor.server.application.*
import io.ktor.server.auth.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import kotlinx.serialization.Serializable
import org.slf4j.LoggerFactory
import uk.gov.communities.delta.auth.plugins.ApiError
import uk.gov.communities.delta.auth.saml.SAMLTokenService
import uk.gov.communities.delta.auth.security.CLIENT_HEADER_AUTH_NAME
import uk.gov.communities.delta.auth.security.ClientPrincipal
import uk.gov.communities.delta.auth.services.DeltaApiTokenService
import uk.gov.communities.delta.auth.services.UserLookupService
import java.time.Instant
import java.time.format.DateTimeFormatter
import java.time.temporal.ChronoUnit

class InternalDeltaApiTokenController(
    private val tokenService: DeltaApiTokenService,
    private val samlTokenService: SAMLTokenService,
    private val userLookupService: UserLookupService
) {
    private val logger = LoggerFactory.getLogger(javaClass)

    fun route(route: Route) {
        route.post {
            validateApiRequestAndReturnSamlToken(call)
        }
    }

    private suspend fun validateApiRequestAndReturnSamlToken(call: ApplicationCall) {
        val apiToken = call.receive<ApiValidationRequest>().token

        logger.atInfo()
            .log("Received API token to SAML token exchange request")

        val validationUserIdentifiers = tokenService.validateApiToken(apiToken)
        if (validationUserIdentifiers != null) {
            val (userCn, clientId, userGuid) = validationUserIdentifiers
            logger.atInfo()
                .addKeyValue("userCn", userCn)
                .log("Generating SAML token for user")
            val systemClient = call.principal<ClientPrincipal>(CLIENT_HEADER_AUTH_NAME)!!

            val validFrom = Instant.now().minus(10, ChronoUnit.MILLIS)
            val validTo = validFrom.plus(GenerateSAMLTokenController.SAML_TOKEN_EXPIRY_HOURS, ChronoUnit.HOURS)
                .truncatedTo(ChronoUnit.SECONDS)

            val token = samlTokenService.generate(
                systemClient.client.samlCredential,
                userLookupService.lookupUserByCN(userCn),
                validFrom,
                validTo
            )

            call.respond(
                GenerateApiSAMLTokenResponse(
                    username = userCn,
                    token = token,
                    expiry = DateTimeFormatter.ISO_INSTANT.format(validTo),
                    clientId = clientId,
                    userGuid = userGuid.toString(),
                )
            )
        } else {
            throw ApiError(
                HttpStatusCode.Unauthorized,
                "invalid_api_token",
                "the api token is not valid or has expired",
            )
        }
    }

    @Serializable
    data class GenerateApiSAMLTokenResponse(
        val username: String,
        val token: String,
        val expiry: String,
        val clientId: String,
        val userGuid: String?,
    )

    @Serializable
    data class ApiValidationRequest(
        val token: String,
    )
}
