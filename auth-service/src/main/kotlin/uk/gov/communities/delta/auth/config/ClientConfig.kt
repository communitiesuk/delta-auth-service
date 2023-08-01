package uk.gov.communities.delta.auth.config

import org.opensaml.security.x509.BasicX509Credential
import org.slf4j.LoggerFactory
import org.slf4j.spi.LoggingEventBuilder

open class Client(val clientId: String, val clientSecret: String, val samlCredential: BasicX509Credential) {
    override fun toString(): String {
        return "Client($clientId)"
    }
}

class OAuthClient(
    clientId: String,
    clientSecret: String,
    samlCredential: BasicX509Credential,
    val redirectUrl: String
) : Client(clientId, clientSecret, samlCredential) {
    override fun toString(): String {
        return "Client($clientId, redirectUrl=$redirectUrl)"
    }
}

class ClientConfig(val clients: List<Client>) {
    companion object {
        fun fromEnv(deltaConfig: DeltaConfig): ClientConfig {
            val deltaWebsiteSecret = Env.getEnv("CLIENT_SECRET_DELTA_WEBSITE")
            val marklogicSecret =
                Env.getRequiredOrDevFallback("CLIENT_SECRET_MARKLOGIC", "dev-marklogic-client-secret")
            // The delta-website-dev client is used during development and on the test environment
            // so that we can develop delta against test without running the auth service locally
            val devDeltaWebsiteSecret =
                Env.getOptionalOrDevFallback("CLIENT_SECRET_DELTA_WEBSITE_DEV", "dev-delta-website-client-secret")

            val samlCredentials = SAMLConfig.credentialsFromEnvironment()

            val marklogic =
                Client("marklogic", marklogicSecret, samlCredentials)
            val deltaWebsite = deltaWebsiteSecret?.let {
                OAuthClient(
                    "delta-website",
                    deltaWebsiteSecret,
                    samlCredentials,
                    deltaConfig.deltaWebsiteUrl + "/login/oauth2/redirect",
                )
            }
            val devDeltaWebsite = devDeltaWebsiteSecret?.let {
                OAuthClient(
                    "delta-website-dev",
                    devDeltaWebsiteSecret,
                    SAMLConfig.insecureHardcodedCredentials(),
                    "http://localhost:8080/login/oauth2/redirect",
                )
            }
            return ClientConfig(listOfNotNull(marklogic, deltaWebsite, devDeltaWebsite))
        }
    }

    val oauthClients = clients.filterIsInstance<OAuthClient>()

    fun log(logger: LoggingEventBuilder) {
        logger.log("Enabled clients {}", clients)
    }
}
