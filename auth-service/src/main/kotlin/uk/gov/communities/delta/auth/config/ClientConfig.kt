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

class ClientConfig(
    private val clientSecretMarklogic: String,
    private val clientSecretDeltaWebsite: String?,
    private val deltaWebsiteRedirectUrl: String,
    private val clientSecretDeltaWebsiteDev: String?,
    private val deltaWebsiteDevRedirectUrl: String,
) {
    companion object {
        private val logger = LoggerFactory.getLogger(Companion::class.java)

        fun fromEnv(deltaConfig: DeltaConfig): ClientConfig {
            val deltaWebsiteSecret = System.getenv("CLIENT_SECRET_DELTA_WEBSITE")
            var deltaWebsiteLocalDevSecret = System.getenv("CLIENT_SECRET_DELTA_WEBSITE_DEV")
            if (deltaWebsiteSecret == null && deltaWebsiteLocalDevSecret == null) {
                logger.info("No Delta client secrets specified, creating local development client")
                deltaWebsiteLocalDevSecret = "dev-delta-website-client-secret"
            }
            return ClientConfig(
                clientSecretMarklogic = System.getenv("CLIENT_SECRET_MARKLOGIC") ?: "dev-marklogic-client-secret",
                clientSecretDeltaWebsite = deltaWebsiteSecret,
                deltaConfig.deltaWebsiteUrl + "/login/oauth2/redirect",
                clientSecretDeltaWebsiteDev = deltaWebsiteLocalDevSecret,
                "http://localhost:8080/login/oauth2/redirect"
            )
        }
    }

    private val marklogic = Client("marklogic", clientSecretMarklogic, SAMLConfig.credentialsFromEnvironmentOrInsecureFallback())
    private val deltaWebsite = clientSecretDeltaWebsite?.let {
        OAuthClient(
            "delta-website",
            clientSecretDeltaWebsite,
            SAMLConfig.credentialsFromEnvironment(),
            deltaWebsiteRedirectUrl,
        )
    }
    private val deltaWebsiteLocal = clientSecretDeltaWebsiteDev?.let {
        OAuthClient(
            "delta-website-dev",
            clientSecretDeltaWebsiteDev,
            SAMLConfig.insecureHardcodedCredentials(),
            deltaWebsiteDevRedirectUrl,
        )
    }
    val clients = listOfNotNull(deltaWebsite, marklogic, deltaWebsiteLocal)
    val oauthClients = clients.filterIsInstance<OAuthClient>()
}
