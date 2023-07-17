package uk.gov.communities.delta.auth.controllers

import io.ktor.http.*
import io.ktor.server.application.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.ktor.server.thymeleaf.*
import org.slf4j.LoggerFactory
import uk.gov.communities.delta.auth.config.DeltaConfig
import uk.gov.communities.delta.auth.security.ADLdapLoginService
import uk.gov.communities.delta.auth.security.LdapUser


class PublicDeltaLoginController(private val ldapService: ADLdapLoginService) {
    private val logger = LoggerFactory.getLogger(this.javaClass)

    suspend fun loginGet(call: ApplicationCall) {
        if (!areOAuthParametersValid(call)) {
            call.respondText("Invalid params") // TODO: Log and redirect back to delta/login?error
        }
        call.respondLoginPage()
    }

    private fun areOAuthParametersValid(call: ApplicationCall): Boolean {
        val checks = mapOf<String, (String?) -> Boolean>(
            "response_type" to { it.equals("code") },
            "client_id" to { it.equals("delta-website") },
            "state" to { !it.isNullOrEmpty() },
        )
        for (check in checks) {
            if (!check.value(call.request.queryParameters[check.key])) {
                logger.warn("Invalid ${check.key} query param for request to delta login {}", call.request.uri)
                return false
            }
        }
        return true
    }

    private suspend fun ApplicationCall.respondLoginPage(
        errorMessage: String = "", errorLink: String = "#", username: String = "", password: String = ""
    ) = respond(
        ThymeleafContent(
            "delta-login",
            mapOf(
                "deltaUrl" to DeltaConfig.DELTA_WEBSITE_URL,
                "errorMessage" to errorMessage,
                "errorLink" to errorLink,
                "username" to username,
                "password" to password,
            )
        )
    )

    suspend fun loginPost(call: ApplicationCall) {
        if (!areOAuthParametersValid(call)) {
            call.respondText("Invalid params") // TODO: Log and redirect back to delta/login?error
        }

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
            is ADLdapLoginService.LdapLoginSuccess -> {
                if (!loginResult.user.isMemberOfDeltaGroup()) {
                    logger.atInfo().addKeyValue("username", cn).addKeyValue("loginFailureType", "NotDeltaUser")
                        .log("Login failed")
                    call.respondLoginPage(
                        errorMessage = "Your account exists but is not set up to access Delta. Please contact the Service Desk.",
                        errorLink = DeltaConfig.DELTA_WEBSITE_URL + "/contact-us",
                        username = formUsername,
                        password = password,
                    )
                }

                logger.atInfo().addKeyValue("username", cn).log("Successful login")

                val state = call.request.queryParameters["state"]!!
                val authCode = "an_auth_code"
                call.respondRedirect(DeltaConfig.DELTA_WEBSITE_URL + "/login/oauth2/redirect?code=${authCode.encodeURLQueryComponent()}&state=${state.encodeURLQueryComponent()}")
            }

            is ADLdapLoginService.LdapLoginFailure -> {
                // There's a risk of logging passwords accidentally typed into the username box,
                // but we're accepting that here for the convenience of being able to see failed logins
                logger.atInfo().addKeyValue("username", cn)
                    .addKeyValue("loginFailureType", loginResult.javaClass.simpleName).log("Login failed")
                val userVisibleError = userVisibleError(loginResult)
                call.respondLoginPage(
                    errorMessage = userVisibleError.errorMessage,
                    errorLink = userVisibleError.link ?: "#",
                    username = formUsername,
                    password = password
                )
            }
        }
    }

    private data class LoginError(val errorMessage: String, val link: String?)

    private fun userVisibleError(ldapError: ADLdapLoginService.LdapLoginFailure): LoginError {
        return when (ldapError) {
            is ADLdapLoginService.DisabledAccount -> LoginError(
                "Your account has been disabled. Please contact the Service Desk",
                DeltaConfig.DELTA_WEBSITE_URL + "/contact-us"
            )

            is ADLdapLoginService.ExpiredPassword -> LoginError(
                "Your password has expired. Please reset your password.",
                DeltaConfig.DELTA_WEBSITE_URL + "/forgot-password"
            )

            is ADLdapLoginService.PasswordNeedsReset -> LoginError(
                "Your password has expired. Please reset your password.",
                DeltaConfig.DELTA_WEBSITE_URL + "/forgot-password"
            )

            is ADLdapLoginService.BadConnection -> LoginError(
                "Error connecting to LDAP server. If this persists please contact the Service Desk",
                DeltaConfig.DELTA_WEBSITE_URL + "/contact-us"
            )

            else -> LoginError(
                "Your username or password are incorrect. Please try again or reset your password. Five incorrect login attempts will lock your account for 30 minutes, you may have to try later.",
                null
            )
        }
    }

    private fun LdapUser.isMemberOfDeltaGroup() = memberOfCNs.contains(DeltaConfig.REQUIRED_GROUP_CN)
}
