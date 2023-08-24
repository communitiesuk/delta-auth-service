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
import kotlin.time.Duration.Companion.seconds

@Serializable
class OrganisationSearchResponse(@SerialName("organisation-results") val organisations: List<Organisation>) {}

@Serializable
class Organisation(
    @SerialName("code") val code: String,
    @SerialName("retired-date") val retiredDate: String? = null
) { //TODO - get actual name for retired-date - this will be used for user creation with retired org domains
}

class OrganisationService(private val httpClient: HttpClient) {
    suspend fun findAllByDomain(domain: String): List<Organisation> {
        return httpClient.get("http://localhost:8030/organisation/search?domain=${domain.encodeURLParameter()}") // TODO - use correct url - environment variable?
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