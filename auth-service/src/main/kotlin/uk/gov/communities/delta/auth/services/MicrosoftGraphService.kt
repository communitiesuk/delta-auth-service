package uk.gov.communities.delta.auth.services

import io.ktor.client.*
import io.ktor.client.call.*
import io.ktor.client.plugins.*
import io.ktor.client.request.*
import io.ktor.http.*
import kotlinx.serialization.Serializable
import org.slf4j.LoggerFactory

class MicrosoftGraphService(
    private val httpClient: HttpClient
) {
    private val logger = LoggerFactory.getLogger(javaClass)
    suspend fun checkCurrentUserGroups(accessToken: String, groupIds: List<String>): List<String> {
        logger.info("Requesting user groups from Microsoft Graph")
        try {
            // TODO: Allow through Network Firewall
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
