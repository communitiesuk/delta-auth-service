package uk.gov.communities.delta.auth.controllers.external

import io.ktor.http.*
import io.ktor.server.application.*
import io.ktor.server.plugins.callid.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import io.ktor.server.sessions.*
import io.ktor.server.thymeleaf.*
import io.micrometer.core.instrument.Counter
import org.slf4j.LoggerFactory
import uk.gov.communities.delta.auth.LoginSessionCookie
import uk.gov.communities.delta.auth.config.*
import uk.gov.communities.delta.auth.oauthClientLoginRoute
import uk.gov.communities.delta.auth.oauthClientLoginRouteWithEmail
import uk.gov.communities.delta.auth.security.IADLdapLoginService
import uk.gov.communities.delta.auth.services.AuthorizationCodeService
import uk.gov.communities.delta.auth.services.LdapUser
import uk.gov.communities.delta.auth.services.withAuthCode


class DeltaLoginController(
    private val authServiceConfig: AuthServiceConfig,
    private val clients: List<DeltaLoginEnabledClient>,
    private val ssoConfig: AzureADSSOConfig,
    private val deltaConfig: DeltaConfig,
    private val ldapService: IADLdapLoginService,
    private val authorizationCodeService: AuthorizationCodeService,
    private val failedLoginCounter: Counter,
    private val successfulLoginCounter: Counter,
) {
    private val logger = LoggerFactory.getLogger(this.javaClass)

    fun loginRoutes(route: Route) {
        route.post {
            loginPost(call)
        }
        route.get {
            loginGet(call)
        }
    }

    private suspend fun loginGet(call: ApplicationCall) {
        val params = call.getLoginQueryParams()
        if (params == null) {
            logger.info("Invalid parameters for login request, redirecting back to Delta")
            return call.respondRedirect(deltaConfig.deltaWebsiteUrl + "/login?error=delta_invalid_params&trace=${call.callId!!.encodeURLParameter()}")
        }
        val client = params.client
        logger.info("Creating login session cookie for client {}", client.clientId)
        call.sessions.set(LoginSessionCookie(deltaState = params.state, clientId = client.clientId))

        if (params.useSSOClient != null) {
            if (params.expectedEmail != null) {
                call.respondRedirect(oauthClientLoginRouteWithEmail(params.useSSOClient.internalId, params.expectedEmail))
            }
            call.respondRedirect(oauthClientLoginRoute(params.useSSOClient.internalId))
        } else {
            call.respondLoginPage(client)
        }
    }

    private class LoginQueryParams(
        val client: DeltaLoginEnabledClient,
        val state: String,
        val useSSOClient: AzureADSSOClient?,
        val expectedEmail: String?,
    )

    private fun ApplicationCall.getLoginQueryParams(): LoginQueryParams? {
        val responseType = request.queryParameters["response_type"]
        val clientId = request.queryParameters["client_id"]
        val state = request.queryParameters["state"]

        if (responseType != "code") {
            logger.warn("Invalid query param response_type, expected 'code'")
            return null
        }
        if (state.isNullOrEmpty()) {
            logger.warn("Query param state is required")
            return null
        }
        val client = clients.singleOrNull { it.clientId == clientId }
        if (client == null) {
            logger.warn("No client found with client id {}", clientId)
            return null
        }
        val ssoClient = request.queryParameters["sso-client"]
            ?.let { param -> ssoConfig.ssoClients.firstOrNull { it.internalId == param } }
        val expectedEmail = request.queryParameters["expected-email"]
        return LoginQueryParams(client, state, ssoClient, expectedEmail)
    }

    private suspend fun ApplicationCall.respondLoginPage(
        client: DeltaLoginEnabledClient,
        errorMessage: String = "",
        errorLink: String = "#",
        username: String = "",
    ) = respond(
        ThymeleafContent(
            "delta-login",
            mapOf(
                "deltaUrl" to client.deltaWebsiteUrl,
                "ssoClients" to ssoConfig.ssoClients.filter { it.buttonText != null },
                "errorMessage" to errorMessage,
                "errorLink" to errorLink,
                "username" to username,
            )
        )
    )

    private suspend fun loginPost(call: ApplicationCall) {
        call.checkOriginHeader()
        val queryParams = call.getLoginQueryParams()
            ?: return call.respondRedirect(deltaConfig.deltaWebsiteUrl + "/login?error=delta_invalid_params&trace=${call.callId!!.encodeURLParameter()}")

        val client = queryParams.client
        val formParameters = call.receiveParameters()
        val formUsername = formParameters["username"]?.trim()
        val password = formParameters["password"]

        if (formUsername.isNullOrEmpty()) return call.respondLoginPage(
            client, errorMessage = "Username is required", errorLink = "#username"
        )
        if (password.isNullOrEmpty()) return call.respondLoginPage(
            client,
            errorMessage = "Password is required",
            errorLink = "#password",
            username = formUsername,
        )

        val ssoClientMatchingEmailDomain = ssoConfig.ssoClients.firstOrNull {
            it.required && formUsername.lowercase().endsWith(it.emailDomain)
        }
        if (ssoClientMatchingEmailDomain != null) {
            return call.respondRedirect(oauthClientLoginRouteWithEmail(ssoClientMatchingEmailDomain.internalId, formUsername))
        }

        val cn = formUsername.replace('@', '!')
        when (val loginResult = ldapService.ldapLogin(cn, password)) {
            is IADLdapLoginService.LdapLoginFailure -> {
                // There's a risk of logging passwords accidentally typed into the username box,
                // but we're accepting that here for the convenience of being able to see failed logins
                logger.atInfo().addKeyValue("username", cn)
                    .addKeyValue("loginFailureType", loginResult.javaClass.simpleName).log("Login failed")
                failedLoginCounter.increment(1.0)
                val userVisibleError = userVisibleError(loginResult)
                call.respondLoginPage(
                    client,
                    errorMessage = userVisibleError.errorMessage,
                    errorLink = userVisibleError.link ?: "#",
                    username = formUsername,
                )
            }

            is IADLdapLoginService.LdapLoginSuccess -> {
                if (!loginResult.user.isMemberOfDeltaGroup()) {
                    logger.atInfo().addKeyValue("username", cn).addKeyValue("loginFailureType", "NotDeltaUser")
                        .log("Login failed")
                    failedLoginCounter.increment(1.0)
                    return call.respondLoginPage(
                        client,
                        errorMessage = "Your account exists but is not set up to access Delta. Please contact the Service Desk.",
                        errorLink = deltaConfig.deltaWebsiteUrl + "/contact-us",
                        username = formUsername,
                    )
                }

                if (loginResult.user.email.isNullOrEmpty()) {
                    logger.atInfo().addKeyValue("username", cn).addKeyValue("loginFailureType", "NoMailAttribute")
                        .log("Login failed")
                    failedLoginCounter.increment(1.0)
                    return call.respondLoginPage(
                        client,
                        errorMessage = "Your account exists but is not fully set up (missing mail attribute). Please contact the Service Desk.",
                        errorLink = deltaConfig.deltaWebsiteUrl + "/contact-us",
                        username = formUsername,
                    )
                }

                val authCode = authorizationCodeService.generateAndStore(
                    userCn = loginResult.user.cn, client = client, traceId = call.callId!!
                )

                logger.atInfo().withAuthCode(authCode).log("Successful login")
                successfulLoginCounter.increment(1.0)
                call.respondRedirect(client.deltaWebsiteUrl + "/login/oauth2/redirect?code=${authCode.code}&state=${queryParams.state.encodeURLParameter()}")
            }
        }
    }

    private data class LoginError(val errorMessage: String, val link: String?)

    private fun userVisibleError(ldapError: IADLdapLoginService.LdapLoginFailure): LoginError {
        return when (ldapError) {
            is IADLdapLoginService.DisabledAccount -> LoginError(
                "Your account has been disabled. Please contact the Service Desk",
                deltaConfig.deltaWebsiteUrl + "/contact-us"
            )

            is IADLdapLoginService.ExpiredPassword -> LoginError(
                "Your password has expired. Please reset your password.",
                deltaConfig.deltaWebsiteUrl + "/forgot-password"
            )

            is IADLdapLoginService.PasswordNeedsReset -> LoginError(
                "Your password has expired. Please reset your password.",
                deltaConfig.deltaWebsiteUrl + "/forgot-password"
            )

            is IADLdapLoginService.BadConnection -> LoginError(
                "Error connecting to LDAP server. If this persists please contact the Service Desk",
                deltaConfig.deltaWebsiteUrl + "/contact-us"
            )

            else -> LoginError(
                "Your username or password are incorrect. Please try again or reset your password. Five incorrect login attempts will lock your account for 30 minutes, you may have to try later.",
                null
            )
        }
    }

    private fun LdapUser.isMemberOfDeltaGroup() = memberOfCNs.contains(deltaConfig.datamartDeltaUser)

    private fun ApplicationCall.checkOriginHeader() {
        val origin = request.headers["Origin"]
        if (origin != authServiceConfig.serviceUrl) {
            logger.warn("Origin header check failure, expected '{}' got '{}' for user agent {}", authServiceConfig.serviceUrl, origin, request.headers["User-Agent"])
            throw InvalidOriginException("Origin header validation failed, expected '${authServiceConfig.serviceUrl}' got '$origin'")
        }
    }

    class InvalidOriginException(message: String) : Exception(message)
}
