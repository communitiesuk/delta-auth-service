package uk.gov.communities.delta.auth.security

import org.slf4j.Logger
import org.slf4j.LoggerFactory
import uk.gov.communities.delta.auth.config.Client
import java.nio.charset.StandardCharsets
import java.security.MessageDigest

class ClientSecretCheck {
    companion object {
        val logger: Logger = LoggerFactory.getLogger(ClientSecretCheck::class.java)

        fun <T : Client>getClient(clients: List<T>, clientId: String, clientSecret: String): T? {
            val client = clients.singleOrNull { it.clientId == clientId }
            if (client == null) {
                logger.warn("No client with id {}", clientId)
                return null
            }

            val requestClientSecretBytes = clientSecret.toByteArray(StandardCharsets.UTF_8)
            val correctSecretBytes = client.clientSecret.toByteArray(StandardCharsets.UTF_8)
            val secretValid = MessageDigest.isEqual(requestClientSecretBytes, correctSecretBytes)

            if (!secretValid) {
                logger.warn("Invalid client secret provided for client {}", clientId)
                return null
            }
            return client
        }
    }
}
