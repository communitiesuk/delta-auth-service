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
import org.slf4j.LoggerFactory
import uk.gov.communities.delta.auth.config.DeltaConfig
import uk.gov.communities.delta.auth.utils.timedSuspend
import java.time.LocalDate
import kotlin.time.Duration.Companion.seconds

@Serializable
class OrganisationSearchResponse(@SerialName("organisation-results") val organisations: List<Organisation>)

@Serializable
class Organisation(
    @SerialName("code") val code: String,
    @SerialName("name") val name: String,
    @SerialName("retirement-date") val retirementDate: String? = null,
) {
    val retired = retirementDate != null && LocalDate.parse(retirementDate.substring(IntRange(0, 9))) < LocalDate.now()
}

@Serializable
class OrganisationNameAndCode(
    @SerialName("code") val code: String,
    @SerialName("name") val name: String,
)

class OrganisationService(private val httpClient: HttpClient, private val deltaConfig: DeltaConfig) {
    private val logger = LoggerFactory.getLogger(javaClass)

    suspend fun findAllByDomain(domain: String): List<Organisation> {
        return logger.timedSuspend(
            "Fetch organisations for domain",
            { listOf(Pair("organisationCount", it.size), Pair("domain", domain)) }) {
            httpClient.get(deltaConfig.masterStoreBaseNoAuth + "organisation/search?domain=${domain.encodeURLParameter()}")
                .body<OrganisationSearchResponse>().organisations
        }
    }

    suspend fun findAllNamesAndCodes(): List<OrganisationNameAndCode> {
        return logger.timedSuspend(
            "Fetch all organisation names and codes",
            { listOf(Pair("organisationCount", it.size)) }) {
            httpClient.get(deltaConfig.masterStoreBaseNoAuth + "organisation/all-names-and-codes")
                .body<List<OrganisationNameAndCode>>()
        }
    }

    companion object {
        fun makeHTTPClient(): HttpClient {
            return HttpClient(Java) {
                install(ContentNegotiation) {
                    json(Json { ignoreUnknownKeys = true })
                }
                install(HttpTimeout) {
                    requestTimeoutMillis = 20.seconds.inWholeMilliseconds
                }
                defaultRequest { headers.append("Accept", "application/json") }
            }
        }
    }
}
