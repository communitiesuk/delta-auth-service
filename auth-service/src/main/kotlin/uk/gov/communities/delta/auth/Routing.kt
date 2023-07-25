package uk.gov.communities.delta.auth

import io.ktor.server.application.*
import io.ktor.server.auth.*
import io.ktor.server.http.content.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import uk.gov.communities.delta.auth.controllers.external.DeltaLoginController
import uk.gov.communities.delta.auth.plugins.addBearerSessionInfoToMDC
import uk.gov.communities.delta.auth.plugins.addClientIdToMDC
import uk.gov.communities.delta.auth.plugins.addServiceUserUsernameToMDC
import uk.gov.communities.delta.auth.security.CLIENT_HEADER_AUTH_NAME
import uk.gov.communities.delta.auth.security.DELTA_AD_LDAP_SERVICE_USERS_AUTH_NAME
import uk.gov.communities.delta.auth.security.DeltaLdapPrincipal
import uk.gov.communities.delta.auth.security.OAUTH_ACCESS_BEARER_TOKEN_AUTH_NAME

fun Application.configureRouting(injection: Injection) {
    routing {
        healthcheckRoute()
        internalRoutes(injection)
        externalRoutes(injection.externalDeltaLoginController())
    }
}

fun Route.healthcheckRoute() {
    get("/health") {
        call.respondText("OK")
    }
}

fun Route.externalRoutes(deltaLoginController: DeltaLoginController) {

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

// "Internal" to the VPC, this is enforced by load balancer rules
fun Route.internalRoutes(injection: Injection) {
    val generateSAMLTokenController = injection.generateSAMLTokenController()
    val oAuthTokenController = injection.internalOAuthTokenController()
    val refreshUserInfoController = injection.refreshUserInfoController()

    route("/auth-internal") {
        authenticate(CLIENT_HEADER_AUTH_NAME, strategy = AuthenticationStrategy.Required) {
            authenticate(DELTA_AD_LDAP_SERVICE_USERS_AUTH_NAME, strategy = AuthenticationStrategy.Required) {
                install(addServiceUserUsernameToMDC)
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
            oAuthTokenController.getToken(call)
        }
        authenticate(CLIENT_HEADER_AUTH_NAME, strategy = AuthenticationStrategy.Required) {
            authenticate(OAUTH_ACCESS_BEARER_TOKEN_AUTH_NAME, strategy = AuthenticationStrategy.Required) {
                install(addClientIdToMDC)
                install(addBearerSessionInfoToMDC)
                route("/bearer") {
                    get("/delta-user") {
                        refreshUserInfoController.getUserInfo(call)
                    }
                }
            }
        }
    }
}
