package uk.gov.communities.delta.auth.services.sso

import io.ktor.http.*
import io.ktor.server.application.*
import io.ktor.server.auth.*
import io.ktor.server.request.*
import io.ktor.server.sessions.*
import org.slf4j.LoggerFactory
import uk.gov.communities.delta.auth.LoginSessionCookie
import uk.gov.communities.delta.auth.config.AzureADSSOClient
import uk.gov.communities.delta.auth.config.AzureADSSOConfig

/*
 * Helper service for configuring the Ktor OAuth plugin, including state checks
 */
class SSOOAuthClientProviderLookupService(
    private val ssoConfig: AzureADSSOConfig,
    private val ssoLoginStateService: SSOLoginSessionStateService,
) {
    private val logger = LoggerFactory.getLogger(javaClass)

    fun validateSSOClientForOAuthRequest(call: ApplicationCall): AzureADSSOClient? {
        val ssoClientId = call.parameters["ssoClientId"]
        val ssoClient = ssoConfig.ssoClients.firstOrNull { it.internalId == ssoClientId }
        if (ssoClient == null) {
            logger.warn("Invalid client id from URL path {}", ssoClientId)
            return null
        }
        if (call.sessions.get<LoginSessionCookie>() == null) {
            logger.warn("OAuth request with no session cookie to {}", call.request.uri)
            return null
        }
        if (call.request.path() == "/delta/oauth/${ssoClient.internalId}/callback") {
            if (call.parameters.contains("error")) {
                logger.warn("OAuth Callback contains error query param")
                return null
            }
            val validateStateResult = ssoLoginStateService.validateCallSSOState(call)
            if (validateStateResult != SSOLoginSessionStateService.ValidateStateResult.VALID) {
                logger.warn("OAuth Callback validate state failed {}", validateStateResult.name)
                return null
            }
        }
        return ssoClient
    }

    fun providerConfig(ssoClient: AzureADSSOClient) =
        OAuthServerSettings.OAuth2ServerSettings(
            name = "azure",
            authorizeUrl = "https://login.microsoftonline.com/${ssoClient.azTenantId}/oauth2/v2.0/authorize",
            accessTokenUrl = "https://login.microsoftonline.com/${ssoClient.azTenantId}/oauth2/v2.0/token",
            requestMethod = HttpMethod.Post,
            clientId = ssoClient.azClientId,
            clientSecret = ssoClient.azClientSecret,
            defaultScopes = listOf(
                "https://graph.microsoft.com/User.Read",
                // TODO DT-528 Do we need this? Email seems to be supplied anyway
                "https://graph.microsoft.com/email",
            ),
            onStateCreated = { call, state ->
                ssoLoginStateService.onSSOStateCreated(call, state, ssoClient)
            }
        )
}
