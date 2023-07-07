package uk.gov.communities.delta.auth.config

class ClientConfig {
    companion object {
        val CLIENT_SECRET_MARKLOGIC = System.getenv("CLIENT_SECRET_MARKLOGIC") ?: "dev-marklogic-client-secret"
    }
}
