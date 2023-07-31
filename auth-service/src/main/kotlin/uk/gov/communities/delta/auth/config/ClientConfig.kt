package uk.gov.communities.delta.auth.config

import org.opensaml.security.x509.BasicX509Credential
import org.slf4j.LoggerFactory

open class Client(val clientId: String, val clientSecret: String, val samlCredential: BasicX509Credential)

class OAuthClient(
    clientId: String,
    clientSecret: String,
    samlCredential: BasicX509Credential,
    val redirectUrl: String
) : Client(clientId, clientSecret, samlCredential)

class ClientConfig(val clients: List<Client>) {
    companion object {
        private val logger = LoggerFactory.getLogger(Companion::class.java)

        fun fromEnv(deltaConfig: DeltaConfig): ClientConfig {
            val deltaWebsiteSecret = Env.getEnv("CLIENT_SECRET_DELTA_WEBSITE")
            val marklogicSecret = Env.getEnvOrDevFallback("CLIENT_SECRET_MARKLOGIC", "dev-marklogic-client-secret")
            var devDeltaWebsiteSecret = Env.getEnv("CLIENT_SECRET_DELTA_WEBSITE_DEV")

            if (deltaWebsiteSecret == null && devDeltaWebsiteSecret == null && Env.devFallbackEnabled) {
                logger.info("No website clients enabled from environment, development fallback client will be created")
                devDeltaWebsiteSecret = "dev-delta-website-client-secret"
            }

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
}
