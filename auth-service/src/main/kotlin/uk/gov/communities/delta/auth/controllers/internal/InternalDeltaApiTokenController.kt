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
import uk.gov.communities.delta.auth.security.DELTA_AD_LDAP_SERVICE_USERS_AUTH_NAME
import uk.gov.communities.delta.auth.security.DeltaLdapPrincipal
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

        val userWithTokenCn = tokenService.validateApiToken(apiToken)
        if (!userWithTokenCn.isNullOrEmpty()) {
            logger.atInfo()
                .addKeyValue("userCn", userWithTokenCn)
                .log("Generating SAML token for user")
            val client = call.principal<ClientPrincipal>(CLIENT_HEADER_AUTH_NAME)!!

            val user = userLookupService.lookupUserByCn(userWithTokenCn)

            val validFrom = Instant.now().minus(10, ChronoUnit.MILLIS)
            val validTo = validFrom.plus(GenerateSAMLTokenController.SAML_TOKEN_EXPIRY_HOURS, ChronoUnit.HOURS)
                .truncatedTo(ChronoUnit.SECONDS)

            val token = samlTokenService.generate(client.client.samlCredential, user, validFrom, validTo)

            call.respond(
                GenerateSAMLTokenController.GenerateSAMLTokenResponse(
                    username = user.cn,
                    token = token,
                    expiry = DateTimeFormatter.ISO_INSTANT.format(validTo),
                )
            )
        }
        else {
            throw ApiError(
                HttpStatusCode.Forbidden,
                "invalid_api_token",
                "the api token is not valid or has expired",
            )
        }
    }

    @Serializable
    data class ApiValidationRequest(
        val token: String,
    )
}
