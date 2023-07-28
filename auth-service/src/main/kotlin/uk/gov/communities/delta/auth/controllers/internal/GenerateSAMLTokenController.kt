package uk.gov.communities.delta.auth.controllers.internal

import io.ktor.server.application.*
import io.ktor.server.auth.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import kotlinx.serialization.Serializable
import uk.gov.communities.delta.auth.saml.SAMLTokenService
import uk.gov.communities.delta.auth.security.DELTA_AD_LDAP_SERVICE_USERS_AUTH_NAME
import uk.gov.communities.delta.auth.security.DeltaLdapPrincipal
import java.time.Instant
import java.time.format.DateTimeFormatter
import java.time.temporal.ChronoUnit

class GenerateSAMLTokenController(private val samlTokenService: SAMLTokenService) {
    fun route(route: Route) {
        route.post {
            generateSAMLToken(call)
        }
    }

    private suspend fun generateSAMLToken(call: ApplicationCall) {
        val user = call.principal<DeltaLdapPrincipal>(DELTA_AD_LDAP_SERVICE_USERS_AUTH_NAME)!!

        val validFrom = Instant.now().minus(10, ChronoUnit.MILLIS)
        val validTo = validFrom.plus(SAML_TOKEN_EXPIRY_HOURS, ChronoUnit.HOURS)
            .truncatedTo(ChronoUnit.SECONDS)

        val token = samlTokenService.generate(user.ldapUser, validFrom, validTo)

        call.respond(
            GenerateSAMLTokenResponse(
                username = user.ldapUser.cn,
                token = token,
                expiry = DateTimeFormatter.ISO_INSTANT.format(validTo),
            )
        )
    }

    @Serializable
    data class GenerateSAMLTokenResponse(
        val username: String,
        val token: String,
        val expiry: String,
    )

    companion object {
        const val SAML_TOKEN_EXPIRY_HOURS = 1L
    }
}
