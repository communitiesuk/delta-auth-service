package uk.gov.communities.delta.auth.plugins

import io.ktor.server.application.*
import io.ktor.server.auth.*
import io.ktor.server.plugins.callid.*
import io.ktor.server.plugins.callloging.*
import kotlinx.coroutines.slf4j.MDCContext
import kotlinx.coroutines.withContext
import org.slf4j.MDC
import org.slf4j.event.Level
import uk.gov.communities.delta.auth.security.*
import uk.gov.communities.delta.auth.services.OAuthSession

fun Application.configureMonitoring() {
    install(CallLogging) {
        level = Level.INFO
        callIdMdc("requestId")
        mdc("username") { it.principal<DeltaLdapPrincipal>(DELTA_AD_LDAP_SERVICE_USERS_AUTH_NAME)?.username }
        disableDefaultColors()
    }
    install(CallId) {
        header("X-Amz-Cf-Id")
        generate(16)
        verify { callId: String ->
            callId.isNotEmpty()
        }
    }
}

internal object BeforeCall : Hook<suspend (ApplicationCall, suspend () -> Unit) -> Unit> {
    override fun install(
        pipeline: ApplicationCallPipeline,
        handler: suspend (ApplicationCall, suspend () -> Unit) -> Unit
    ) {
        pipeline.intercept(ApplicationCallPipeline.Call) {
            handler(call, ::proceed)
        }
    }
}

// The call logging plugin doesn't update the MDC after the authentication phase by default, so add as an extra step
val addServiceUserUsernameToMDC = createRouteScopedPlugin("AddUsernameToMdc") {
    on(BeforeCall) { call, proceed ->
        val username = call.principal<DeltaLdapPrincipal>(DELTA_AD_LDAP_SERVICE_USERS_AUTH_NAME)!!.username
        val mdcContextMap = MDC.getCopyOfContextMap() ?: mutableMapOf()
        mdcContextMap["username"] = username
        withContext(MDCContext(mdcContextMap)) {
            proceed()
        }
    }
}

val addClientIdToMDC = createRouteScopedPlugin("AddClientIdToMDC") {
    on(BeforeCall) { call, proceed ->
        val clientId = call.principal<ClientPrincipal>(CLIENT_HEADER_AUTH_NAME)!!.clientId
        val mdcContextMap = MDC.getCopyOfContextMap() ?: mutableMapOf()
        mdcContextMap["clientId"] = clientId
        withContext(MDCContext(mdcContextMap)) {
            proceed()
        }
    }
}

val addBearerSessionInfoToMDC = createRouteScopedPlugin("AddBearerSessionInfoToMDC") {
    on(BeforeCall) { call, proceed ->
        val session = call.principal<OAuthSession>(OAUTH_ACCESS_BEARER_TOKEN_AUTH_NAME)!!
        val mdcContextMap = MDC.getCopyOfContextMap() ?: mutableMapOf()
        mdcContextMap["username"] = session.userCn
        mdcContextMap["oauthSession"] = session.id.toString()
        mdcContextMap["trace"] = session.traceId
        withContext(MDCContext(mdcContextMap)) {
            proceed()
        }
    }
}
