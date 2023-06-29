package uk.gov.communities.delta.auth.security

import io.ktor.server.application.*
import io.ktor.server.auth.*


fun Application.configureSecurity() {
    val deltaADLdapAuthentication = DeltaADLdapAuthentication()

    authentication {
        basic(name = DeltaADLdapAuthentication.NAME) {
            realm = "Delta"
            validate { credentials ->
                deltaADLdapAuthentication.authenticate(credentials)
            }
        }
    }
}
