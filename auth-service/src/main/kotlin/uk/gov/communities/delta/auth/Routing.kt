package uk.gov.communities.delta.auth

import io.ktor.server.application.*
import io.ktor.server.auth.*
import io.ktor.server.http.content.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import uk.gov.communities.delta.auth.plugins.addUsernameToMdc
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
        externalRoutes()
    }
}

fun Route.healthcheckRoute() {
    get("/health") {
        call.respondText("OK")
    }
}

fun Route.externalRoutes() {
    val publicDeltaLoginController = Injection.publicDeltaLoginController()

    route("/auth-external") {
        staticResources("/static", "static")
        route("/delta") {
            route("/login") {
                get {
                    publicDeltaLoginController.loginGet(call)
                }
                post {
                    publicDeltaLoginController.loginPost(call)
                }
            }
        }
    }
}

// "Internal" to the VPC, this is enforced by load balancer rules
fun Route.internalRoutes() {
    val generateSAMLTokenController = Injection.generateSAMLTokenController()

    route("/auth-internal") {
        authenticate(CLIENT_AUTH_NAME, strategy = AuthenticationStrategy.Required) {
            authenticate(DELTA_AD_LDAP_SERVICE_USERS_AUTH_NAME, strategy = AuthenticationStrategy.Required) {
                install(addUsernameToMdc)
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
        post("/token") {
            // TODO
            // Should no-cache
            call.respond(mapOf(
                "access_token" to "my_access_token",
                "token_type" to "bearer",
                "expires_in" to "43200",
                "delta_user" to "delta.admin",
            ))
        }
    }
}
