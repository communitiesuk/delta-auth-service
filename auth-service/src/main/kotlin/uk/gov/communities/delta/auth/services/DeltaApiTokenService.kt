package uk.gov.communities.delta.auth.services

import uk.gov.communities.delta.auth.repositories.DbPool

class DeltaApiTokenService(private val dbPool: DbPool) {
    fun createAndStoreApiToken(): String {
        throw NotImplementedError()
    }

    fun validateApiToken(apiToken: String): Boolean {
        throw NotImplementedError()
    }

    fun generateApiSamlToken(): String {
        throw NotImplementedError()
    }
}
