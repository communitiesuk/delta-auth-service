package uk.gov.communities.delta.auth

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

        healthcheckRoute()

        authenticate(DeltaADLdapAuthentication.NAME) {
            internalRoutes()
        }
    }
}

fun Route.healthcheckRoute() {
    get("/health") {
        call.respondText("OK")
    }
}

// "Internal" to the VPC, this is enforced by load balancer rules
fun Route.internalRoutes() {
    val generateSAMLTokenController = Injection.generateSAMLTokenController()

    route("/auth-internal") {
        get("/auth-diag") {
            val principal = call.principal<DeltaLdapPrincipal>(DeltaADLdapAuthentication.NAME)!!
            call.respond(principal)
        }
        post("/generate-saml-token") {
            generateSAMLTokenController.generateSAMLToken(call)
        }
    }
}
