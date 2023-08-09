package uk.gov.communities.delta.auth

import io.ktor.http.*
import io.ktor.server.application.*
import io.ktor.server.auth.*
import io.ktor.server.http.content.*
import io.ktor.server.plugins.ratelimit.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import io.ktor.server.sessions.*
import io.ktor.util.*
import kotlinx.serialization.Serializable
import uk.gov.communities.delta.auth.config.AuthServiceConfig
import uk.gov.communities.delta.auth.config.Env
import uk.gov.communities.delta.auth.controllers.external.DeltaLoginController
import uk.gov.communities.delta.auth.controllers.external.DeltaSSOLoginController
import uk.gov.communities.delta.auth.controllers.internal.GenerateSAMLTokenController
import uk.gov.communities.delta.auth.controllers.internal.OAuthTokenController
import uk.gov.communities.delta.auth.controllers.internal.RefreshUserInfoController
import uk.gov.communities.delta.auth.plugins.CSP
import uk.gov.communities.delta.auth.plugins.addBearerSessionInfoToMDC
import uk.gov.communities.delta.auth.plugins.addClientIdToMDC
import uk.gov.communities.delta.auth.plugins.addServiceUserUsernameToMDC
import uk.gov.communities.delta.auth.security.*
import java.io.File

// A session cookie used during the login flow and cleared after.
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
        externalRoutes(injection.authServiceConfig, injection.externalDeltaLoginController(), injection.deltaOAuthLoginController())
    }
}

fun Route.healthcheckRoute() {
    get("/health") {
        call.respondText("OK")
    }
}

fun Route.externalRoutes(
    serviceConfig: AuthServiceConfig,
    deltaLoginController: DeltaLoginController,
    deltaSSOLoginController: DeltaSSOLoginController,
) {
    install(CSP)
    staticResources("/static", "static")
    // We override the link in our HTML, but this saves us some spurious 404s when browsers request it anyway
    get("/favicon.ico") {
        call.respondBytes(javaClass.classLoader.getResourceAsStream("static/assets/images/favicon.ico")!!.readAllBytes(), ContentType.Image.XIcon)
    }

    route("/delta") {
        deltaLoginRoutes(serviceConfig, deltaLoginController, deltaSSOLoginController)
    }
}

fun Route.deltaLoginRoutes(
    serviceConfig: AuthServiceConfig,
    deltaLoginController: DeltaLoginController,
    deltaSSOLoginController: DeltaSSOLoginController,
) {
    install(Sessions) {
        val key = hex(Env.getRequiredOrDevFallback("COOKIE_SIGNING_KEY_HEX", "1234"))
        cookie<LoginSessionCookie>("LOGIN_SESSION") {
            cookie.extensions["SameSite"] = "Lax" // We need the cookie to be present when being redirected back to the SSO callback endpoint
            cookie.secure = serviceConfig.serviceUrl.startsWith("https")
            transform(SessionTransportTransformerMessageAuthentication(key))
        }
    }

    route("/login") {
        rateLimit(RateLimitName(loginRateLimitName)) {
            deltaLoginController.loginRoutes(this)
        }
    }

    route("/oauth/{ssoClientId}/") {
        authenticate(SSO_AZURE_AD_OAUTH_CLIENT) {
            deltaSSOLoginController.route(this)
        }
    }
}

fun oauthClientLoginRoute(ssoClientInternalId: String) = "/delta/oauth/${ssoClientInternalId}/login"
fun oauthClientCallbackRoute(ssoClientInternalId: String) = "/delta/oauth/${ssoClientInternalId}/callback"

// "Internal" to the VPC, this is enforced by load balancer rules
fun Route.internalRoutes(injection: Injection) {
    val generateSAMLTokenController = injection.generateSAMLTokenController()
    val oauthTokenController = injection.internalOAuthTokenController()
    val refreshUserInfoController = injection.refreshUserInfoController()

    route("/auth-internal") {
        serviceUserRoutes(generateSAMLTokenController)

        oauthTokenRoute(oauthTokenController)

        bearerTokenRoutes(refreshUserInfoController)
    }
}

fun Route.oauthTokenRoute(oauthTokenController: OAuthTokenController) {
    route("/token") {
        oauthTokenController.route(this)
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
