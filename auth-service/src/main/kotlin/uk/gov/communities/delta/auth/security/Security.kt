package uk.gov.communities.delta.auth.security

import io.ktor.server.application.*
import io.ktor.server.auth.*
import org.slf4j.LoggerFactory
import uk.gov.communities.delta.auth.Injection
import uk.gov.communities.delta.auth.config.OAuthClient

// "Delta-Client: client-id:secret" header auth for internal APIs
const val CLIENT_HEADER_AUTH_NAME = "delta-client-header-auth"

// Basic auth with Active Directory service user credentials for internal APIs
const val DELTA_AD_LDAP_SERVICE_USERS_AUTH_NAME = "delta-ldap-service-users-basic"

// Bearer token with an access token issued by this service's /auth-internal/token endpoint for internal APIs
// Requires client header auth
const val OAUTH_ACCESS_BEARER_TOKEN_AUTH_NAME = "oauth-bearer-access-token"

fun Application.configureSecurity(injection: Injection) {
    val ldapAuthenticationService = injection.ldapServiceUserAuthenticationService()
    val oAuthSessionService = injection.oAuthSessionService
    val logger = LoggerFactory.getLogger("Application.Security")

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
    }
}
