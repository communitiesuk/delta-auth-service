package uk.gov.communities.delta.auth.plugins

import io.ktor.server.application.*
import io.ktor.server.auth.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import uk.gov.communities.delta.auth.security.DeltaADLdapAuthentication
import uk.gov.communities.delta.auth.security.DeltaLdapPrincipal

fun Application.configureRouting() {
    routing {
        get("/") {
            call.respondText("Hello World!")
        }
        authenticate(DeltaADLdapAuthentication.NAME) {
            get("/authenticated") {
                call.respondText("Authenticated! " + call.principal<DeltaLdapPrincipal>(DeltaADLdapAuthentication.NAME)!!.cn)
            }
        }
    }
}
