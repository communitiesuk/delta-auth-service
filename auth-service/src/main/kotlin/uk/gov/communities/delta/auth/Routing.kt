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
import uk.gov.communities.delta.auth.config.DeltaConfig
import uk.gov.communities.delta.auth.config.Env
import uk.gov.communities.delta.auth.controllers.external.*
import uk.gov.communities.delta.auth.controllers.internal.*
import uk.gov.communities.delta.auth.plugins.*
import uk.gov.communities.delta.auth.security.*

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
    installCachingHeaders()
    routing {
        healthcheckRoute()
        internalRoutes(injection)
        externalRoutes(
            injection.authServiceConfig,
            injection.deltaConfig,
            injection.externalDeltaLoginController(),
            injection.deltaOAuthLoginController(),
            injection.externalDeltaUserRegisterController(),
            injection.externalDeltaSetPasswordController(),
            injection.externalDeltaResetPasswordController(),
            injection.externalDeltaForgotPasswordController(),
        )
    }
}

fun Route.healthcheckRoute() {
    get("/health") {
        call.respondText("OK")
    }
}

fun Route.externalRoutes(
    serviceConfig: AuthServiceConfig,
    deltaConfig: DeltaConfig,
    deltaLoginController: DeltaLoginController,
    deltaSSOLoginController: DeltaSSOLoginController,
    deltaUserRegistrationController: DeltaUserRegistrationController,
    deltaSetPasswordController: DeltaSetPasswordController,
    deltaResetPasswordController: DeltaResetPasswordController,
    deltaForgotPasswordController: DeltaForgotPasswordController,
) {
    staticResources("/static", "static") {
        cacheControl { listOf(CacheControl.MaxAge(86400)) } // Currently set to 1 day
    }.apply {
        install(BrowserSecurityHeaders)
    }

    val faviconBytes = javaClass.classLoader.getResourceAsStream("static/assets/images/favicon.ico")!!.readAllBytes()

    // We override the link in our HTML, but this saves us some spurious 404s when browsers request it anyway
    get("/favicon.ico") {
        call.respondBytes(
            faviconBytes,
            ContentType.Image.XIcon
        )
    }

    route("/delta") {
        install(originHeaderCheck(serviceConfig.serviceUrl, deltaConfig))
        install(BrowserSecurityHeaders)

        route("/register") {
            deltaRegisterRoutes(deltaUserRegistrationController)
        }

        route("/set-password") {
            deltaSetPasswordRoutes(deltaSetPasswordController)
        }

        route("/reset-password") {
            deltaResetPasswordRoutes(deltaResetPasswordController)
        }

        route("/forgot-password") {
            deltaForgotPasswordRoutes(deltaForgotPasswordController)
        }

        route("/") {
            deltaLoginRoutes(serviceConfig, deltaLoginController, deltaSSOLoginController)
        }
    }
}

fun Route.deltaSetPasswordRoutes(deltaSetPasswordController: DeltaSetPasswordController) {
    route("/success") {
        deltaSetPasswordController.setPasswordSuccessRoute(this)
    }
    route("/expired") {
        deltaSetPasswordController.setPasswordExpired(this)
    }
    rateLimit(RateLimitName(setPasswordRateLimitName)) {
        deltaSetPasswordController.setPasswordFormRoutes(this)
    }
}

fun Route.deltaResetPasswordRoutes(deltaResetPasswordController: DeltaResetPasswordController) {
    route("/success") {
        deltaResetPasswordController.resetPasswordSuccessRoute(this)
    }
    route("/expired") {
        deltaResetPasswordController.resetPasswordExpired(this)
    }
    rateLimit(RateLimitName(resetPasswordRateLimitName)) {
        deltaResetPasswordController.resetPasswordFormRoutes(this)
    }
}

fun Route.deltaForgotPasswordRoutes(deltaForgotPasswordController: DeltaForgotPasswordController) {
    route("/email-sent") {
        deltaForgotPasswordController.forgotPasswordEmailSentRoute(this)
    }
    rateLimit(RateLimitName(forgotPasswordRateLimitName)) {
        deltaForgotPasswordController.forgotPasswordFormRoutes(this)
    }
}

fun Route.deltaRegisterRoutes(
    deltaUserRegistrationController: DeltaUserRegistrationController,
) {
    route("/success") {
        deltaUserRegistrationController.registerSuccessRoute(this)
    }

    rateLimit(RateLimitName(registrationRateLimitName)) {
        deltaUserRegistrationController.registerFormRoutes(this)
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
            cookie.extensions["SameSite"] =
                "Lax" // We need the cookie to be present when being redirected back to the SSO callback endpoint
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

fun deltaWebsiteLoginRoute(deltaUrl: String, ssoClientInternalId: String?, email: String?, redirectReason: String?): String {
    return "$deltaUrl/oauth2/authorization/delta-auth" +
            mapOf("sso-client" to ssoClientInternalId, "expected-email" to email, "reason" to redirectReason)
                .mapNotNull { if (it.value != null) "${it.key}=${it.value!!.encodeURLParameter()}" else null }
                .joinToString(prefix = "?", separator = "&")
}

fun oauthClientLoginRoute(ssoClientInternalId: String, email: String? = null) =
    if (email == null)
        "/delta/oauth/${ssoClientInternalId}/login"
    else
        "/delta/oauth/${ssoClientInternalId}/login?expected-email=${email.encodeURLParameter()}"

fun oauthClientCallbackRoute(ssoClientInternalId: String) = "/delta/oauth/${ssoClientInternalId}/callback"

// "Internal" to the VPC, this is enforced by load balancer rules
fun Route.internalRoutes(injection: Injection) {
    val generateSAMLTokenController = injection.generateSAMLTokenController()
    val oauthTokenController = injection.internalOAuthTokenController()
    val refreshUserInfoController = injection.refreshUserInfoController()
    val fetchUserAuditController = injection.fetchUserAuditController()
    val adminEmailController = injection.adminEmailController()
    val adminUserCreationController = injection.adminUserCreationController()
    val adminEditUserController = injection.adminEditUserController()
    val adminGetUserController = injection.adminGetUserController()
    val editRolesController = injection.editRolesController()
    val adminEnableDisableUserController = injection.adminEnableDisableUserController()

    route("/auth-internal") {
        serviceUserRoutes(generateSAMLTokenController)

        oauthTokenRoute(oauthTokenController)

        bearerTokenRoutes(
            refreshUserInfoController,
            adminEmailController,
            fetchUserAuditController,
            adminUserCreationController,
            adminEditUserController,
            adminGetUserController,
            editRolesController,
            adminEnableDisableUserController,
        )
    }
}

fun Route.oauthTokenRoute(oauthTokenController: OAuthTokenController) {
    route("/token") {
        oauthTokenController.route(this)
    }
}

fun Route.withBearerTokenAuth(routes: Route.() -> Unit) {
    authenticate(CLIENT_HEADER_AUTH_NAME, strategy = AuthenticationStrategy.Required) {
        authenticate(OAUTH_ACCESS_BEARER_TOKEN_AUTH_NAME, strategy = AuthenticationStrategy.Required) {
            install(addClientIdToMDC)
            install(addBearerSessionInfoToMDC)

            routes()
        }
    }
}

fun Route.bearerTokenRoutes(
    refreshUserInfoController: RefreshUserInfoController,
    adminEmailController: AdminEmailController,
    fetchUserAuditController: FetchUserAuditController,
    adminUserCreationController: AdminUserCreationController,
    adminEditUserController: AdminEditUserController,
    adminGetUserController: AdminGetUserController,
    editRolesController: EditRolesController,
    adminEnableDisableUserController: AdminEnableDisableUserController,
) {
    route("/bearer") {
        withBearerTokenAuth {
            route("/user-info") {
                refreshUserInfoController.route(this)
            }
            route("/user-audit") {
                fetchUserAuditController.route(this)
            }
            route("/create-user") {
                adminUserCreationController.route(this)
            }
            route("/edit-user") {
                adminEditUserController.route(this)
            }
            route("/get-user") {
                adminGetUserController.route(this)
            }
            route("/email") {
                adminEmailController.route(this)
            }
            route("/roles") {
                editRolesController.route(this)
            }
            post("/admin/enable-user") {
                adminEnableDisableUserController.enableUser(call)
            }
            post("/admin/disable-user") {
                adminEnableDisableUserController.disableUser(call)
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
