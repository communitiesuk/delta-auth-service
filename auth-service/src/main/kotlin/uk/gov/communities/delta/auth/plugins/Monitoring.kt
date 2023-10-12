package uk.gov.communities.delta.auth.plugins

import io.ktor.server.application.*
import io.ktor.server.auth.*
import io.ktor.server.metrics.micrometer.*
import io.ktor.server.plugins.*
import io.ktor.server.plugins.callid.*
import io.ktor.server.plugins.callloging.*
import io.micrometer.core.instrument.MeterRegistry
import io.micrometer.core.instrument.config.MeterFilter
import kotlinx.coroutines.slf4j.MDCContext
import kotlinx.coroutines.withContext
import org.slf4j.MDC
import org.slf4j.event.Level
import uk.gov.communities.delta.auth.security.CLIENT_HEADER_AUTH_NAME
import uk.gov.communities.delta.auth.security.ClientPrincipal
import uk.gov.communities.delta.auth.security.DELTA_AD_LDAP_SERVICE_USERS_AUTH_NAME
import uk.gov.communities.delta.auth.security.DeltaLdapPrincipal
import uk.gov.communities.delta.auth.services.OAuthSession
import kotlin.collections.set

fun Application.configureMonitoring(meterRegistry: MeterRegistry) {
    install(CallLogging) {
        level = Level.INFO
        callIdMdc("requestId")
        // Temporarily enable call logging for health checks
        //  filter { it.request.path() != "/health" }
        mdc("username") { it.principal<DeltaLdapPrincipal>(DELTA_AD_LDAP_SERVICE_USERS_AUTH_NAME)?.username }
        mdc("IPAddress") { it.request.origin.remoteAddress }
        disableDefaultColors()
    }
    install(CallId) {
        header("X-Amz-Cf-Id")
        generate(16)
        verify { callId: String ->
            callId.isNotEmpty()
        }
    }
    install(MicrometerMetrics) {
        registry = meterRegistry
        meterBinders = emptyList()
        registry.config()
            .meterFilter(MeterFilter.acceptNameStartsWith("login."))
            .meterFilter(MeterFilter.acceptNameStartsWith("registration."))
            .meterFilter(MeterFilter.acceptNameStartsWith("setPassword."))
            .meterFilter(MeterFilter.acceptNameStartsWith("tasks."))
            .meterFilter(MeterFilter.deny()) // Currently don't want any other metrics
    }
}

internal object BeforeCall : Hook<suspend (ApplicationCall, suspend () -> Unit) -> Unit> {
    override fun install(
        pipeline: ApplicationCallPipeline,
        handler: suspend (ApplicationCall, suspend () -> Unit) -> Unit,
    ) {
        pipeline.intercept(ApplicationCallPipeline.Call) {
            handler(call, ::proceed)
        }
    }
}

// The call logging plugin doesn't update the MDC after the authentication phase by default, so add as an extra step
val addServiceUserUsernameToMDC = createRouteScopedPlugin("AddUsernameToMdc") {
    on(BeforeCall) { call, proceed ->
        val principal = call.principal<DeltaLdapPrincipal>(DELTA_AD_LDAP_SERVICE_USERS_AUTH_NAME) ?: return@on proceed()
        val mdcContextMap = MDC.getCopyOfContextMap() ?: mutableMapOf()
        mdcContextMap["username"] = principal.username
        withContext(MDCContext(mdcContextMap)) {
            proceed()
        }
    }
}

val addClientIdToMDC = createRouteScopedPlugin("AddClientIdToMDC") {
    on(BeforeCall) { call, proceed ->
        val principal = call.principal<ClientPrincipal>(CLIENT_HEADER_AUTH_NAME) ?: return@on proceed()
        val mdcContextMap = MDC.getCopyOfContextMap() ?: mutableMapOf()
        mdcContextMap["clientId"] = principal.client.clientId
        withContext(MDCContext(mdcContextMap)) {
            proceed()
        }
    }
}

val addBearerSessionInfoToMDC = createRouteScopedPlugin("AddBearerSessionInfoToMDC") {
    on(BeforeCall) { call, proceed ->
        val session = call.principal<OAuthSession>() ?: return@on proceed()
        val mdcContextMap = MDC.getCopyOfContextMap() ?: mutableMapOf()
        mdcContextMap["username"] = session.userCn
        mdcContextMap["oauthSession"] = session.id.toString()
        mdcContextMap["trace"] = session.traceId
        withContext(MDCContext(mdcContextMap)) {
            proceed()
        }
    }
}
