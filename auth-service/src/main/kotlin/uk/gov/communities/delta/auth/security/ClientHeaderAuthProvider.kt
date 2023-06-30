package uk.gov.communities.delta.auth.security

import io.ktor.http.*
import io.ktor.server.auth.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import org.slf4j.LoggerFactory
import java.nio.charset.StandardCharsets
import java.security.MessageDigest

/**
 * Custom auth provider, expects header of the form
 *
 * Header: client-id:client-secret
 *
 * Where the header name and clients are configurable
 */
class ClientHeaderAuthProvider(private val config: Config) : AuthenticationProvider(config) {

    companion object {
        private val headerValueRegex = Regex("^([\\w-]+):([\\w-]+)")
    }

    private val logger = LoggerFactory.getLogger(ClientHeaderAuthProvider::class.java)

    override suspend fun onAuthenticate(context: AuthenticationContext) {
        val headerValue = context.call.request.header(config.headerName)
        if (headerValue == null) {
            logger.warn("No {} header present", config.headerName)
            return context.reject(AuthenticationFailedCause.NoCredentials, "${config.headerName} header required")
        }

        val match = headerValueRegex.matchEntire(headerValue)
        if (match == null) {
            logger.warn("Invalid {} header value {}", config.headerName, headerValue)
            return context.reject(AuthenticationFailedCause.NoCredentials, "Invalid ${config.headerName} header format")
        }

        val clientId = match.groups[1]!!.value
        val clientSecret = match.groups[2]!!.value
        val client = config.clients.singleOrNull { it.clientId == clientId }
        if (client == null) {
            logger.warn("No client with id {}", clientId)
            return context.reject(AuthenticationFailedCause.InvalidCredentials, "Invalid client id or secret")
        }

        val requestClientSecretBytes = clientSecret.toByteArray(StandardCharsets.UTF_8)
        val correctSecretBytes = client.clientSecret.toByteArray(StandardCharsets.UTF_8)
        val secretValid = MessageDigest.isEqual(requestClientSecretBytes, correctSecretBytes)

        if (!secretValid) {
            logger.warn("Invalid client secret provided for client {}", clientId)
            return context.reject(AuthenticationFailedCause.InvalidCredentials, "Invalid client id or secret")
        }

        context.principal(ClientPrincipal(clientId))
    }

    private fun AuthenticationContext.reject(cause: AuthenticationFailedCause, message: String) {
        challenge(config.name!!, cause) { challenge, call ->
            call.respondText(message, status = HttpStatusCode.Unauthorized)
            challenge.complete()
        }
    }

    data class Client(val clientId: String, val clientSecret: String)

    data class ClientPrincipal(val clientId: String) : Principal

    class Config(name: String) : AuthenticationProvider.Config(name) {
        lateinit var clients: List<Client>
        lateinit var headerName: String
    }
}

fun AuthenticationConfig.clientHeaderAuth(
    name: String,
    configure: ClientHeaderAuthProvider.Config.() -> Unit
) {
    val provider = ClientHeaderAuthProvider(ClientHeaderAuthProvider.Config(name).apply(configure))
    register(provider)
}
