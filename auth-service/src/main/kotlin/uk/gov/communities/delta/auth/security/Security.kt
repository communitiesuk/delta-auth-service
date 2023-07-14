package uk.gov.communities.delta.auth.security

import io.ktor.server.application.*
import io.ktor.server.auth.*
import uk.gov.communities.delta.auth.Injection
import uk.gov.communities.delta.auth.config.ClientConfig

const val CLIENT_AUTH_NAME = "delta-client-header-auth"
const val DELTA_AD_LDAP_SERVICE_USERS_AUTH_NAME = "delta-ldap-service-users-basic"

fun Application.configureSecurity() {
    val ldapAuthenticationService = Injection.ldapServiceUserAuthenticationService()

    authentication {
        basic(DELTA_AD_LDAP_SERVICE_USERS_AUTH_NAME) {
            realm = "Delta"
            validate { credentials ->
                ldapAuthenticationService.authenticate(credentials)
            }
        }

        clientHeaderAuth(CLIENT_AUTH_NAME) {
            headerName = "Delta-Client"
            clients = listOf(ClientHeaderAuthProvider.Client("marklogic", ClientConfig.CLIENT_SECRET_MARKLOGIC))
        }
    }
}
