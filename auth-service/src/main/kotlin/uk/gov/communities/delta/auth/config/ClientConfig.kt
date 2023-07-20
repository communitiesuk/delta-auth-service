package uk.gov.communities.delta.auth.config

data class Client(val clientId: String, val clientSecret: String)

class ClientConfig(
    private val clientSecretMarklogic: String,
    private val clientSecretDeltaWebsite: String,
) {
    companion object {
        fun fromEnv() = ClientConfig(
            clientSecretMarklogic = System.getenv("CLIENT_SECRET_MARKLOGIC") ?: "dev-marklogic-client-secret",
            clientSecretDeltaWebsite = System.getenv("CLIENT_SECRET_DELTA_WEBSITE")
                ?: "dev-delta-website-client-secret",
        )
    }

    val deltaWebsite = Client("delta-website", clientSecretDeltaWebsite)
    val marklogic = Client("marklogic", clientSecretMarklogic)
    val clients = listOf(deltaWebsite, marklogic)
}
