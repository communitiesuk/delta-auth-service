package uk.gov.communities.delta.auth.controllers.internal

import io.ktor.server.application.*
import io.ktor.server.plugins.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.ktor.server.util.*
import org.slf4j.LoggerFactory
import uk.gov.communities.delta.auth.config.ClientConfig
import uk.gov.communities.delta.auth.services.IAuthorizationCodeService
import java.nio.charset.StandardCharsets
import java.security.MessageDigest

class OAuthTokenController(
    private val authorizationCodeService: IAuthorizationCodeService
) {
    private val logger = LoggerFactory.getLogger(javaClass)

    suspend fun getToken(call: ApplicationCall) {
        val params = call.receiveParameters()
        val code = params.getOrFail("code")
        val clientId = params.getOrFail("client_id")
        val clientSecret = params.getOrFail("client_secret")

        if (clientId != "delta-website") {
            logger.error("Client id mismatch {}", clientId)
            throw BadRequestException("Invalid client id")
        }
        if (!compareClientSecret(clientSecret, ClientConfig.CLIENT_SECRET_DELTA_WEBSITE)) {
            logger.error("Invalid client secret for {}", clientId)
            throw BadRequestException("Invalid client secret")
        }

        val authCode = authorizationCodeService.lookupAndInvalidate(code) ?: throw BadRequestException("Invalid code")

        call.respond(
            mapOf(
                "access_token" to "unused_for_now",
                "token_type" to "bearer",
                "expires_in" to "43200",
                "delta_user" to authCode.userCn,
            )
        )
    }

    private fun compareClientSecret(req: String, correct: String): Boolean {
        val requestClientSecretBytes = req.toByteArray(StandardCharsets.UTF_8)
        val correctSecretBytes = correct.toByteArray(StandardCharsets.UTF_8)
        return MessageDigest.isEqual(requestClientSecretBytes, correctSecretBytes)
    }
}
