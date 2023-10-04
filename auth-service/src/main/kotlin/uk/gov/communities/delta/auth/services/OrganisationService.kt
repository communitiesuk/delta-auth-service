package uk.gov.communities.delta.auth.services

import io.ktor.client.*
import io.ktor.client.call.*
import io.ktor.client.engine.java.*
import io.ktor.client.plugins.*
import io.ktor.client.plugins.contentnegotiation.*
import io.ktor.client.request.*
import io.ktor.http.*
import io.ktor.serialization.kotlinx.json.*
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import uk.gov.communities.delta.auth.config.DeltaConfig
import java.time.LocalDate
import kotlin.time.Duration.Companion.seconds

@Serializable
class OrganisationSearchResponse(@SerialName("organisation-results") val organisations: List<Organisation>)

@Serializable
class Organisation(
    @SerialName("code") val code: String,
    @SerialName("retirement-date") val retirementDate: String? = null
) {
    val retired = retirementDate != null && LocalDate.parse(retirementDate.substring(IntRange(0, 9))) < LocalDate.now()
}

class OrganisationService(private val httpClient: HttpClient, private val deltaConfig: DeltaConfig) {
    suspend fun findAllByDomain(domain: String): List<Organisation> {
        return httpClient.get(deltaConfig.masterStoreBaseNoAuth + "organisation/search?domain=${domain.encodeURLParameter()}")
            .body<OrganisationSearchResponse>().organisations
    }

    companion object {
        fun makeHTTPClient(): HttpClient {
            return HttpClient(Java) {
                install(ContentNegotiation) {
                    json(Json { ignoreUnknownKeys = true })
                }
                install(HttpTimeout) {
                    requestTimeoutMillis = 10.seconds.inWholeMilliseconds
                }
                defaultRequest { headers.append("Accept", "application/json") }
            }
        }
    }
}