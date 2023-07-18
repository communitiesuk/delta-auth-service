package uk.gov.communities.delta.auth.controllers.internal

import io.ktor.server.application.*
import io.ktor.server.auth.*
import io.ktor.server.response.*
import kotlinx.serialization.Serializable
import uk.gov.communities.delta.auth.config.SAMLConfig
import uk.gov.communities.delta.auth.saml.SAMLTokenService
import uk.gov.communities.delta.auth.security.DELTA_AD_LDAP_SERVICE_USERS_AUTH_NAME
import uk.gov.communities.delta.auth.security.DeltaLdapPrincipal
import java.nio.charset.StandardCharsets
import java.time.Instant
import java.time.format.DateTimeFormatter
import java.time.temporal.ChronoUnit
import java.util.*

class GenerateSAMLTokenController(private val samlTokenService: SAMLTokenService) {

    suspend fun generateSAMLToken(call: ApplicationCall) {
        val user = call.principal<DeltaLdapPrincipal>(DELTA_AD_LDAP_SERVICE_USERS_AUTH_NAME)!!

        val validFrom = Instant.now().minus(10, ChronoUnit.MILLIS)
        val validTo = validFrom.plus(SAMLConfig.SAML_TOKEN_EXPIRY_HOURS.toLong(), ChronoUnit.HOURS)
            .truncatedTo(ChronoUnit.SECONDS)

        val token = samlTokenService.generate(user, validFrom, validTo)
        val encodedToken = base64Encode(token)

        call.respond(
            GenerateSAMLTokenResponse(
                username = user.cn,
                token = encodedToken,
                expiry = DateTimeFormatter.ISO_INSTANT.format(validTo),
            )
        )
    }

    private fun base64Encode(s: String): String {
        val bytes = s.toByteArray(StandardCharsets.UTF_8)
        return String(Base64.getEncoder().encode(bytes), StandardCharsets.UTF_8)
    }

    @Serializable
    data class GenerateSAMLTokenResponse(
        val username: String,
        val token: String,
        val expiry: String,
    )
}
