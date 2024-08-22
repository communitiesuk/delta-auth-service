package uk.gov.communities.delta.auth.services.sso

import io.ktor.client.*
import io.ktor.client.call.*
import io.ktor.client.engine.java.*
import io.ktor.client.plugins.*
import io.ktor.client.plugins.contentnegotiation.*
import io.ktor.client.request.*
import io.ktor.http.*
import io.ktor.serialization.kotlinx.json.*
import io.opentelemetry.api.OpenTelemetry
import io.opentelemetry.instrumentation.ktor.v2_0.client.KtorClientTracing
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import org.slf4j.LoggerFactory
import org.slf4j.MDC
import kotlin.time.Duration.Companion.seconds

class MicrosoftGraphService(openTelemetry: OpenTelemetry) {
    private val logger = LoggerFactory.getLogger(javaClass)
    private val httpClient = HttpClient(Java) {
        install(ContentNegotiation) {
            json(Json { ignoreUnknownKeys = true })
        }
        install(HttpTimeout) {
            requestTimeoutMillis = 10.seconds.inWholeMilliseconds
        }
        install(KtorClientTracing) {
            setOpenTelemetry(openTelemetry)
            attributeExtractor {
                onStart {
                    attributes.put("peer.service", "Microsoft Graph")
                    attributes.put("delta.request-to", "microsoft-graph")
                    attributes.put("MDC-requestId", MDC.get("requestId"))
                }
            }
        }
    }

    // See https://learn.microsoft.com/en-us/graph/api/directoryobject-checkmembergroups
    suspend fun checkCurrentUserGroups(accessToken: String, groupIds: List<String>): List<String> {
        logger.info("Requesting user groups from Microsoft Graph")
        try {
            val response = httpClient.post("https://graph.microsoft.com/v1.0/me/checkMemberGroups") {
                bearerAuth(accessToken)
                headers {
                    append(HttpHeaders.Accept, "application/json")
                }
                contentType(ContentType.Application.Json)
                setBody(CheckMemberGroupsRequest(groupIds))
                expectSuccess = true
            }
            return response.body<CheckMemberGroupsResponse>().value
        } catch (e: Exception) {
            logger.error("Request to Microsoft Graph checkMemberGroups failed with exception", e)
            throw e
        }
    }

    @Serializable
    private class CheckMemberGroupsRequest(@Suppress("unused") val groupIds: List<String>)

    @Serializable
    private class CheckMemberGroupsResponse(val value: List<String>)
}
