package uk.gov.communities.delta.auth.controllers.internal

import io.ktor.server.application.*
import io.ktor.server.auth.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import kotlinx.serialization.Serializable
import org.slf4j.LoggerFactory
import uk.gov.communities.delta.auth.saml.SAMLTokenService
import uk.gov.communities.delta.auth.security.CLIENT_HEADER_AUTH_NAME
import uk.gov.communities.delta.auth.security.ClientPrincipal
import uk.gov.communities.delta.auth.security.DELTA_AD_LDAP_SERVICE_USERS_AUTH_NAME
import uk.gov.communities.delta.auth.security.DeltaLdapPrincipal
import uk.gov.communities.delta.auth.services.DeltaApiTokenService
import java.time.Instant
import java.time.format.DateTimeFormatter
import java.time.temporal.ChronoUnit

class InternalDeltaApiTokenController(
    private val tokenService: DeltaApiTokenService,
    private val samlTokenService: SAMLTokenService,
) {
    private val logger = LoggerFactory.getLogger(javaClass)
    fun route(route: Route) {
        route.post {
            validateApiRequestAndReturnSamlToken(call)
        }
    }

    // TODO 836 is this what I want this method to be called?
    private suspend fun validateApiRequestAndReturnSamlToken(call: ApplicationCall) {
        val apiToken = call.receive<ApiValidationRequest>().token

        if (tokenService.validateApiToken(apiToken)) {
            // TODO 836 lots of repeated code with generatesamltokencontroller - move into service? maybe not tbh
            val user = call.principal<DeltaLdapPrincipal>(DELTA_AD_LDAP_SERVICE_USERS_AUTH_NAME)!!
            val client = call.principal<ClientPrincipal>(CLIENT_HEADER_AUTH_NAME)!!

            val validFrom = Instant.now().minus(10, ChronoUnit.MILLIS)
            val validTo = validFrom.plus(GenerateSAMLTokenController.SAML_TOKEN_EXPIRY_HOURS, ChronoUnit.HOURS)
                .truncatedTo(ChronoUnit.SECONDS)

            val token = samlTokenService.generate(client.client.samlCredential, user.ldapUser, validFrom, validTo)

            call.respond(
                GenerateSAMLTokenController.GenerateSAMLTokenResponse(
                    username = user.ldapUser.cn,
                    token = token,
                    expiry = DateTimeFormatter.ISO_INSTANT.format(validTo),
                )
            )
        }
    }

    @Serializable
    data class ApiValidationRequest(
        val token: String,
    )
}
