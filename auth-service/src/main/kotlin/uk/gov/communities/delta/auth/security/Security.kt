package uk.gov.communities.delta.auth.security

import io.ktor.client.*
import io.ktor.client.engine.java.*
import io.ktor.client.plugins.contentnegotiation.*
import io.ktor.http.*
import io.ktor.serialization.kotlinx.json.*
import io.ktor.server.application.*
import io.ktor.server.auth.*
import io.ktor.server.request.*
import io.ktor.server.sessions.*
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import uk.gov.communities.delta.auth.Injection
import uk.gov.communities.delta.auth.LoginSessionCookie
import uk.gov.communities.delta.auth.config.AzureADSSOConfig
import uk.gov.communities.delta.auth.config.OAuthClient
import uk.gov.communities.delta.auth.config.ServiceConfig

// "Delta-Client: client-id:secret" header auth for internal APIs
const val CLIENT_HEADER_AUTH_NAME = "delta-client-header-auth"

// Basic auth with Active Directory service user credentials for internal APIs
const val DELTA_AD_LDAP_SERVICE_USERS_AUTH_NAME = "delta-ldap-service-users-basic"

// Bearer token with an access token issued by this service's /auth-internal/token endpoint for internal APIs
// Requires client header auth
const val OAUTH_ACCESS_BEARER_TOKEN_AUTH_NAME = "oauth-bearer-access-token"

// Single Sign On through Azure AD, should only be used by the login and callback routes directly involved in SSO
const val OAUTH_CLIENT_TO_AZURE_AD = "oauth-client-to-azure-ad"

fun Application.configureSecurity(injection: Injection) {
    val logger = LoggerFactory.getLogger("Application.Security")
    val ldapAuthenticationService = injection.ldapServiceUserAuthenticationService()
    val oAuthSessionService = injection.oAuthSessionService
    val ssoLoginStateService = injection.ssoLoginStateService
    val serviceConfig = injection.serviceConfig
    val ssoConfig = injection.azureADSSOConfig
    val oauthHttpClient = HttpClient(Java) {
        install(ContentNegotiation) {
            json()
        }
    }

    authentication {
        basic(DELTA_AD_LDAP_SERVICE_USERS_AUTH_NAME) {
            realm = "Delta"
            validate { credentials ->
                ldapAuthenticationService.authenticate(credentials)
            }
        }

        clientHeaderAuth(CLIENT_HEADER_AUTH_NAME) {
            headerName = "Delta-Client"
            clients = injection.clientConfig.clients
        }

        bearer(OAUTH_ACCESS_BEARER_TOKEN_AUTH_NAME) {
            realm = "auth-service"
            authenticate {
                val clientPrincipal = principal<ClientPrincipal>(CLIENT_HEADER_AUTH_NAME)
                if (clientPrincipal == null) {
                    logger.warn("OAuth Bearer token authentication, rejecting due to missing client authentication")
                    return@authenticate null
                }
                oAuthSessionService.retrieveFomAuthToken(it.token, clientPrincipal.client as OAuthClient)
            }
        }

        deltaOAuth(serviceConfig, ssoConfig, ssoLoginStateService, oauthHttpClient, logger)
    }
}

fun AuthenticationConfig.deltaOAuth(
    serviceConfig: ServiceConfig,
    ssoConfig: AzureADSSOConfig,
    ssoLoginStateService: SSOLoginStateService,
    oauthHttpClient: HttpClient,
    logger: Logger
) {
    oauth(OAUTH_CLIENT_TO_AZURE_AD) {
        urlProvider = { "${serviceConfig.serviceUrl}/delta/oauth/${parameters["ssoClientId"]!!}/callback" }
        providerLookup = lookup@{
            // This gets executed during the authentication phase of every request under OAuth authentication.
            // We use it to do some extra checks and skip OAuth if we don't want to carry on with the flow.
            val ssoClientId = parameters["ssoClientId"]
            val ssoClient = ssoConfig.ssoClients.firstOrNull { it.internalClientId == ssoClientId }
            if (ssoClient == null) {
                logger.warn("Invalid client id from URL path {}", ssoClientId)
                return@lookup null // Skip authentication and carry straight on to the route handlers
            }
            if (sessions.get<LoginSessionCookie>() == null) {
                logger.warn("OAuth request with no session cookie to {}", request.uri)
                return@lookup null
            }
            if (request.path() == "/delta/oauth/${ssoClient.internalClientId}/callback") {
                if (parameters.contains("error")) {
                    logger.warn("OAuth Callback contains error query param")
                    return@lookup null
                }
                val validateStateResult = ssoLoginStateService.validateCallSSOState(this)
                if (validateStateResult != SSOLoginStateService.ValidateStateResult.VALID) {
                    logger.warn("OAuth Callback validate state failed {}", validateStateResult.name)
                    return@lookup null
                }
            }
            OAuthServerSettings.OAuth2ServerSettings(
                name = "azure",
                authorizeUrl = "https://login.microsoftonline.com/${ssoClient.azTenantId}/oauth2/v2.0/authorize",
                accessTokenUrl = "https://login.microsoftonline.com/${ssoClient.azTenantId}/oauth2/v2.0/token",
                requestMethod = HttpMethod.Post,
                clientId = ssoClient.azClientId,
                clientSecret = ssoClient.azClientSecret,
                defaultScopes = listOf(
                    "https://graph.microsoft.com/User.Read",
                    // TODO Do we need this? Email seems to be supplied anyway
                    "https://graph.microsoft.com/email"
                ),
                onStateCreated = { call, state ->
                    ssoLoginStateService.onSSOStateCreated(call, state, ssoClient)
                }
            )
        }
        client = oauthHttpClient
    }
}
