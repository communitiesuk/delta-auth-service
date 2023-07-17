package uk.gov.communities.delta.auth.security

import io.ktor.server.application.*
import io.ktor.server.auth.*
import uk.gov.communities.delta.auth.Injection

const val CLIENT_AUTH_NAME = "delta-client-header-auth"
const val DELTA_AD_LDAP_SERVICE_USERS_AUTH_NAME = "delta-ldap-service-users-basic"

fun Application.configureSecurity() {
    val ldapAuthenticationService = Injection.instance.ldapServiceUserAuthenticationService()

    authentication {
        basic(DELTA_AD_LDAP_SERVICE_USERS_AUTH_NAME) {
            realm = "Delta"
            validate { credentials ->
                ldapAuthenticationService.authenticate(credentials)
            }
        }

        clientHeaderAuth(CLIENT_AUTH_NAME) {
            headerName = "Delta-Client"
            clients = Injection.instance.clientConfig.clients
        }
    }
}
