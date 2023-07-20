package uk.gov.communities.delta.auth

import io.ktor.server.application.*
import io.ktor.server.auth.*
import io.ktor.server.http.content.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import uk.gov.communities.delta.auth.controllers.external.DeltaLoginController
import uk.gov.communities.delta.auth.controllers.internal.GenerateSAMLTokenController
import uk.gov.communities.delta.auth.controllers.internal.OAuthTokenController
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
        internalRoutes(
            Injection.instance.generateSAMLTokenController(),
            Injection.instance.internalOAuthTokenController()
        )
        externalRoutes(Injection.instance.externalDeltaLoginController())
    }
}

fun Route.healthcheckRoute() {
    get("/health") {
        call.respondText("OK")
    }
}

fun Route.externalRoutes(deltaLoginController: DeltaLoginController) {

    route("/auth-external") {
        staticResources("/static", "static")
        route("/delta") {
            route("/login") {
                get {
                    deltaLoginController.loginGet(call)
                }
                post {
                    deltaLoginController.loginPost(call)
                }
            }
        }
    }
}

// "Internal" to the VPC, this is enforced by load balancer rules
fun Route.internalRoutes(
    generateSAMLTokenController: GenerateSAMLTokenController,
    oAuthTokenController: OAuthTokenController
) {
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
            oAuthTokenController.getToken(call)
        }
    }
}
