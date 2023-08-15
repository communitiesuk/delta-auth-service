package uk.gov.communities.delta.auth.controllers.external

import io.ktor.http.*
import io.ktor.server.application.*
import io.ktor.server.plugins.callid.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import io.ktor.server.thymeleaf.*
import org.slf4j.LoggerFactory
import uk.gov.communities.delta.auth.config.DeltaConfig
import uk.gov.communities.delta.auth.config.OAuthClient
import uk.gov.communities.delta.auth.security.IADLdapLoginService
import uk.gov.communities.delta.auth.services.IAuthorizationCodeService
import uk.gov.communities.delta.auth.services.LdapUser
import uk.gov.communities.delta.auth.services.withAuthCode


class DeltaLoginController(
    private val clients: List<OAuthClient>,
    private val deltaConfig: DeltaConfig,
    private val ldapService: IADLdapLoginService,
    private val authenticationCodeService: IAuthorizationCodeService,
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
        if (call.getLoginQueryParams() == null) {
            logger.info("Invalid parameters for login request, redirecting back to Delta")
            return call.respondRedirect(deltaConfig.deltaWebsiteUrl + "/login?error=delta_invalid_params")
        }
        call.respondLoginPage()
    }

    private class LoginQueryParams(val client: OAuthClient, val state: String)

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
        return LoginQueryParams(client, state)
    }

    private suspend fun ApplicationCall.respondLoginPage(
        errorMessage: String = "", errorLink: String = "#", username: String = "", password: String = ""
    ) = respond(
        ThymeleafContent(
            "delta-login",
            mapOf(
                "deltaUrl" to deltaConfig.deltaWebsiteUrl,
                "errorMessage" to errorMessage,
                "errorLink" to errorLink,
                "username" to username,
                "password" to password,
            )
        )
    )

    private suspend fun loginPost(call: ApplicationCall) {
        val queryParams = call.getLoginQueryParams()
            ?: return call.respondRedirect(deltaConfig.deltaWebsiteUrl + "/login?error=delta_invalid_params")

        val formParameters = call.receiveParameters()
        val formUsername = formParameters["username"]
        val password = formParameters["password"]

        if (formUsername.isNullOrEmpty()) return call.respondLoginPage(
            errorMessage = "Username is required", errorLink = "#username"
        )
        if (password.isNullOrEmpty()) return call.respondLoginPage(
            errorMessage = "Password is required",
            errorLink = "#password",
            username = formUsername,
        )

        val cn = formUsername.replace('@', '!')
        when (val loginResult = ldapService.ldapLogin(cn, password)) {
            is IADLdapLoginService.LdapLoginFailure -> {
                // There's a risk of logging passwords accidentally typed into the username box,
                // but we're accepting that here for the convenience of being able to see failed logins
                logger.atInfo().addKeyValue("username", cn)
                    .addKeyValue("loginFailureType", loginResult.javaClass.simpleName).log("Login failed")
                val userVisibleError = userVisibleError(loginResult)
                call.respondLoginPage(
                    errorMessage = userVisibleError.errorMessage,
                    errorLink = userVisibleError.link ?: "#",
                    username = formUsername,
                )
            }

            is IADLdapLoginService.LdapLoginSuccess -> {
                if (!loginResult.user.isMemberOfDeltaGroup()) {
                    logger.atInfo().addKeyValue("username", cn).addKeyValue("loginFailureType", "NotDeltaUser")
                        .log("Login failed")
                    call.respondLoginPage(
                        errorMessage = "Your account exists but is not set up to access Delta. Please contact the Service Desk.",
                        errorLink = deltaConfig.deltaWebsiteUrl + "/contact-us",
                        username = formUsername,
                    )
                }

                val authCode = authenticationCodeService.generateAndStore(
                    userCn = loginResult.user.cn, client = queryParams.client, traceId = call.callId!!
                )

                logger.atInfo().withAuthCode(authCode).log("Successful login")
                call.respondRedirect(queryParams.client.redirectUrl + "?code=${authCode.code}&state=${queryParams.state.encodeURLParameter()}")
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

    private fun LdapUser.isMemberOfDeltaGroup() = memberOfCNs.contains(deltaConfig.requiredGroupCn)
}
