package uk.gov.communities.delta.auth.config

import org.opensaml.security.x509.BasicX509Credential
import org.slf4j.spi.LoggingEventBuilder
import uk.gov.communities.delta.auth.deltaWebsiteLoginRoute

open class Client(val clientId: String, val clientSecret: String, val samlCredential: BasicX509Credential) {
    override fun toString(): String {
        return "Client($clientId)"
    }
}

class DeltaLoginEnabledClient(
    clientId: String,
    clientSecret: String,
    samlCredential: BasicX509Credential,
    val deltaWebsiteUrl: String,
) : Client(clientId, clientSecret, samlCredential) {
    override fun toString(): String {
        return "Client($clientId, deltaWebsiteUrl=$deltaWebsiteUrl)"
    }

    fun websiteLoginRoute(ssoClientInternalId: String?, email: String?, redirectReason: String?): String =
        deltaWebsiteLoginRoute(deltaWebsiteUrl, ssoClientInternalId, email, redirectReason)
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
            val deltaApiSecret = Env.getRequiredOrDevFallback("CLIENT_SECRET_DELTA_API", "dev-api-client-secret")
            val samlCredentials = SAMLConfig.credentialsFromEnvironment()

            val marklogic =
                Client("marklogic", marklogicSecret, samlCredentials)
            val deltaWebsite = deltaWebsiteSecret?.let {
                DeltaLoginEnabledClient(
                    "delta-website",
                    deltaWebsiteSecret,
                    samlCredentials,
                    deltaConfig.deltaWebsiteUrl,
                )
            }
            val devDeltaWebsiteToTestEnvironment = devDeltaWebsiteSecret?.let {
                DeltaLoginEnabledClient(
                        "delta-website-dev-with-test-ml",
                        devDeltaWebsiteSecret,
                        samlCredentials,
                        "http://localhost:8080",
                )
            }
            val devDeltaWebsite = devDeltaWebsiteSecret?.let {
                DeltaLoginEnabledClient(
                    "delta-website-dev",
                    devDeltaWebsiteSecret,
                    SAMLConfig.insecureHardcodedCredentials(),
                    "http://localhost:8080",
                )
            }
            val deltaApi = Client("delta-api", deltaApiSecret, samlCredentials)
            return ClientConfig(listOfNotNull(marklogic, deltaWebsite, devDeltaWebsite, devDeltaWebsiteToTestEnvironment, deltaApi))
        }
    }

    val oauthClients = clients.filterIsInstance<DeltaLoginEnabledClient>()

    fun log(logger: LoggingEventBuilder) {
        logger.log("Enabled clients {}", clients)
    }
}
