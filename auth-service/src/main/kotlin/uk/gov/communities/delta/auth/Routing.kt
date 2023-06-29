package uk.gov.communities.delta.auth

import io.ktor.server.application.*
import io.ktor.server.auth.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import uk.gov.communities.delta.auth.security.DeltaADLdapAuthentication
import uk.gov.communities.delta.auth.security.DeltaLdapPrincipal

fun Application.configureRouting() {
    val generateSAMLTokenController = Injection.generateSAMLTokenController()

    routing {
        get("/") {
            call.respondText("Hello World!")
        }
        route("/auth-internal") {
            authenticate(DeltaADLdapAuthentication.NAME) {
                get("/auth-diag") {
                    val principal = call.principal<DeltaLdapPrincipal>(DeltaADLdapAuthentication.NAME)!!
                    call.respond(principal)
                }
                post("/generate-saml-token") {
                    generateSAMLTokenController.generateSAMLToken(call)
                }
            }
        }
    }
}
