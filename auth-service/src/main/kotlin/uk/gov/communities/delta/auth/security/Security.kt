package uk.gov.communities.delta.auth.security

import io.ktor.client.*
import io.ktor.client.engine.java.*
import io.ktor.client.plugins.*
import io.ktor.client.plugins.contentnegotiation.*
import io.ktor.serialization.kotlinx.json.*
import io.ktor.server.application.*
import io.ktor.server.auth.*
import io.ktor.server.request.*
import org.slf4j.LoggerFactory
import uk.gov.communities.delta.auth.Injection
import uk.gov.communities.delta.auth.config.AuthServiceConfig
import uk.gov.communities.delta.auth.config.DeltaLoginEnabledClient
import uk.gov.communities.delta.auth.oauthClientCallbackRoute
import uk.gov.communities.delta.auth.services.sso.SSOOAuthClientProviderLookupService
import kotlin.time.Duration.Companion.seconds

// "Delta-Client: client-id:secret" header auth for internal APIs
const val CLIENT_HEADER_AUTH_NAME = "delta-client-header-auth"

// Basic auth with Active Directory service user credentials for internal APIs
const val DELTA_AD_LDAP_SERVICE_USERS_AUTH_NAME = "delta-ldap-service-users-basic"

// Bearer token with an access token issued by this service's /auth-internal/token endpoint for internal APIs
// Requires client header auth
const val OAUTH_ACCESS_BEARER_TOKEN_AUTH_NAME = "oauth-bearer-access-token"

// Single Sign On through Azure AD, only used by the login and callback routes directly involved in SSO
const val SSO_AZURE_AD_OAUTH_CLIENT = "oauth-client-to-azure-ad"

fun Application.configureSecurity(injection: Injection) {
    val logger = LoggerFactory.getLogger("Application.Security")
    val ldapAuthenticationService = injection.ldapServiceUserAuthenticationService()
    val oauthSessionService = injection.oauthSessionService
    val serviceConfig = injection.authServiceConfig
    val oauthClientProviderLookupService = injection.ssoOAuthClientProviderLookupService
    val oauthHttpClient = HttpClient(Java) {
        install(ContentNegotiation) {
            json()
        }
        install(HttpTimeout) {
            requestTimeoutMillis = 10.seconds.inWholeMilliseconds
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
                oauthSessionService.retrieveFomAuthToken(it.token, clientPrincipal.client as DeltaLoginEnabledClient)
            }
        }

        azureAdSingleSignOn(serviceConfig, oauthHttpClient, oauthClientProviderLookupService)
    }
}

fun AuthenticationConfig.azureAdSingleSignOn(
    authServiceConfig: AuthServiceConfig,
    oauthHttpClient: HttpClient,
    ssoOAuthClientProviderLookupService: SSOOAuthClientProviderLookupService,
) {
    val logger = LoggerFactory.getLogger("Application.SSO")
    oauth(SSO_AZURE_AD_OAUTH_CLIENT) {
        urlProvider = { "${authServiceConfig.serviceUrl}${oauthClientCallbackRoute(parameters["ssoClientId"]!!)}" }
        providerLookup = lookup@{
            logger.debug("OAuth provider lookup for request to {}", request.uri)
            // This gets executed during the authentication phase of every request under OAuth authentication.
            // We use it to do some extra checks and skip OAuth if we don't want to carry on with the flow.
            val ssoClient = ssoOAuthClientProviderLookupService.validateSSOClientForOAuthRequest(this)
                ?: return@lookup null // Skip authentication and carry straight on to the route handlers
            logger.debug("Validated sso client for OAuth provider lookup for request to {}", request.uri)
            return@lookup ssoOAuthClientProviderLookupService.providerConfig(ssoClient, parameters["email"]) // TODO - does this return null if there isn't a parameter
        }
        client = oauthHttpClient
    }
}
