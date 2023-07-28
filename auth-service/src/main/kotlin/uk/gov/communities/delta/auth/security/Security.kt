package uk.gov.communities.delta.auth.security

import io.ktor.server.application.*
import io.ktor.server.auth.*
import uk.gov.communities.delta.auth.Injection

// "Delta-Client: client-id:secret" header auth for internal APIs
const val CLIENT_HEADER_AUTH_NAME = "delta-client-header-auth"

// Basic auth with Active Directory service user credentials for internal APIs
const val DELTA_AD_LDAP_SERVICE_USERS_AUTH_NAME = "delta-ldap-service-users-basic"

// Bearer token with an access token issued by this service's /auth-internal/token endpoint for internal APIs
const val OAUTH_ACCESS_BEARER_TOKEN_AUTH_NAME = "oauth-bearer-access-token"

fun Application.configureSecurity(injection: Injection) {
    val ldapAuthenticationService = injection.ldapServiceUserAuthenticationService()
    val oAuthSessionService = injection.oAuthSessionService

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
                oAuthSessionService.retrieveFomAuthToken(it.token)
            }
        }
    }
}
