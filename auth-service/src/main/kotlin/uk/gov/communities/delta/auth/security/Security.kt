package uk.gov.communities.delta.auth.security

import io.ktor.server.application.*
import io.ktor.server.auth.*
import uk.gov.communities.delta.auth.Injection


fun Application.configureSecurity() {
    val deltaADLdapAuthentication = Injection.deltaADLdapAuthentication()

    authentication {
        basic(name = DeltaADLdapAuthentication.NAME) {
            realm = "Delta"
            validate { credentials ->
                deltaADLdapAuthentication.authenticate(credentials)
            }
        }
    }
}
