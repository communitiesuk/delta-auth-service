package uk.gov.communities.delta.auth

import io.ktor.server.application.*
import io.ktor.server.auth.*
import io.ktor.server.http.content.*
import io.ktor.server.plugins.ratelimit.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import io.ktor.server.sessions.*
import io.ktor.util.*
import kotlinx.serialization.Serializable
import uk.gov.communities.delta.auth.config.Env
import uk.gov.communities.delta.auth.controllers.external.DeltaLoginController
import uk.gov.communities.delta.auth.controllers.external.DeltaOAuthLoginController
import uk.gov.communities.delta.auth.controllers.internal.GenerateSAMLTokenController
import uk.gov.communities.delta.auth.controllers.internal.OAuthTokenController
import uk.gov.communities.delta.auth.controllers.internal.RefreshUserInfoController
import uk.gov.communities.delta.auth.plugins.addBearerSessionInfoToMDC
import uk.gov.communities.delta.auth.plugins.addClientIdToMDC
import uk.gov.communities.delta.auth.plugins.addServiceUserUsernameToMDC
import uk.gov.communities.delta.auth.security.*
import java.io.File

@Serializable
data class LoginSessionCookie(
    val deltaState: String,
    val clientId: String,
    val ssoState: String? = null,
    val ssoAt: Long? = null,
    val ssoClient: String? = null,
)

fun Application.configureRouting(injection: Injection) {
    routing {
        healthcheckRoute()
        internalRoutes(injection)
        externalRoutes(injection.externalDeltaLoginController(), injection.deltaOAuthLoginController())
    }
}

fun Route.healthcheckRoute() {
    get("/health") {
        call.respondText("OK")
    }
}

fun Route.externalRoutes(
    deltaLoginController: DeltaLoginController,
    deltaOAuthLoginController: DeltaOAuthLoginController,
) {
    staticResources("/static", "static")
    // We override the link in our HTML, but this saves us some spurious 404s when browsers request it anyway
    get("/favicon.ico") {
        call.respondFile(File(javaClass.classLoader.getResource("static/assets/images/favicon.ico")!!.toURI()))
    }

    route("/delta") {
        deltaLoginRoutes(deltaLoginController, deltaOAuthLoginController)
    }
}

fun Route.deltaLoginRoutes(
    deltaLoginController: DeltaLoginController,
    deltaOAuthLoginController: DeltaOAuthLoginController,
) {
    install(Sessions) {
        // TODO Add Terraform configuration for this
        val key = hex(Env.getRequiredOrDevFallback("COOKIE_SIGNING_KEY_HEX", "1234"))
        cookie<LoginSessionCookie>("LOGIN_SESSION") {
            cookie.extensions["SameSite"] = "strict"
            transform(SessionTransportTransformerMessageAuthentication(key))
        }
    }

    route("/login") {
        rateLimit(RateLimitName(loginRateLimitName)) {
            deltaLoginController.loginRoutes(this)
        }
    }

    route("/oauth/{ssoClientId}/") {
        authenticate(OAUTH_CLIENT_TO_AZURE_AD) {
            deltaOAuthLoginController.route(this)
        }
    }
}

// "Internal" to the VPC, this is enforced by load balancer rules
fun Route.internalRoutes(injection: Injection) {
    val generateSAMLTokenController = injection.generateSAMLTokenController()
    val oAuthTokenController = injection.internalOAuthTokenController()
    val refreshUserInfoController = injection.refreshUserInfoController()

    route("/auth-internal") {
        serviceUserRoutes(generateSAMLTokenController)

        oauthTokenRoute(oAuthTokenController)

        bearerTokenRoutes(refreshUserInfoController)
    }
}

fun Route.oauthTokenRoute(oAuthTokenController: OAuthTokenController) {
    route("/token") {
        oAuthTokenController.route(this)
    }
}

fun Route.bearerTokenRoutes(refreshUserInfoController: RefreshUserInfoController) {
    authenticate(CLIENT_HEADER_AUTH_NAME, strategy = AuthenticationStrategy.Required) {
        authenticate(OAUTH_ACCESS_BEARER_TOKEN_AUTH_NAME, strategy = AuthenticationStrategy.Required) {
            install(addClientIdToMDC)
            install(addBearerSessionInfoToMDC)
            route("/bearer/user-info") {
                refreshUserInfoController.route(this)
            }
        }
    }
}

fun Route.serviceUserRoutes(samlTokenController: GenerateSAMLTokenController) {
    authenticate(CLIENT_HEADER_AUTH_NAME, strategy = AuthenticationStrategy.Required) {
        authenticate(DELTA_AD_LDAP_SERVICE_USERS_AUTH_NAME, strategy = AuthenticationStrategy.Required) {
            install(addServiceUserUsernameToMDC)
            route("/service-user") {
                get("/auth-diag") {
                    val principal = call.principal<DeltaLdapPrincipal>(DELTA_AD_LDAP_SERVICE_USERS_AUTH_NAME)!!
                    call.respond(principal)
                }
                route("/generate-saml-token") {
                    samlTokenController.route(this)
                }
            }
        }
    }
}
