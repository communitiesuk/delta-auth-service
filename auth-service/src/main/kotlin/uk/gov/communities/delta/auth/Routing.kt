package uk.gov.communities.delta.auth

import io.ktor.server.application.*
import io.ktor.server.auth.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import uk.gov.communities.delta.auth.security.CLIENT_AUTH_NAME
import uk.gov.communities.delta.auth.security.DELTA_AD_LDAP_SERVICE_USERS_AUTH_NAME
import uk.gov.communities.delta.auth.security.DeltaLdapPrincipal

fun Application.configureRouting() {

    routing {
        get("/") {
            call.respondText("Hello World!")
        }

        healthcheckRoute()
        internalRoutes()
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

    authenticate(CLIENT_AUTH_NAME, strategy = AuthenticationStrategy.Required) {
        route("/auth-internal") {
            authenticate(DELTA_AD_LDAP_SERVICE_USERS_AUTH_NAME, strategy = AuthenticationStrategy.Required) {
                route("/service-user") {
                    get("/auth-diag") {
                        val principal = call.principal<DeltaLdapPrincipal>(DELTA_AD_LDAP_SERVICE_USERS_AUTH_NAME)!!
                        call.respond(principal)
                    }
                    post("/generate-saml-token") {
                        generateSAMLTokenController.generateSAMLToken(call)
                    }
                }
            }
        }
    }
}
