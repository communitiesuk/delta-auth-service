package uk.gov.communities.delta.auth.plugins.monitoring

import io.ktor.server.application.*
import io.ktor.server.auth.*
import io.ktor.server.plugins.*
import io.ktor.server.plugins.callid.*
import io.ktor.server.request.*
import io.opentelemetry.api.trace.Span
import kotlinx.coroutines.slf4j.MDCContext
import kotlinx.coroutines.withContext
import org.slf4j.MDC
import uk.gov.communities.delta.auth.plugins.BeforeCall
import uk.gov.communities.delta.auth.plugins.BeforeMonitoring
import uk.gov.communities.delta.auth.security.CLIENT_HEADER_AUTH_NAME
import uk.gov.communities.delta.auth.security.ClientPrincipal
import uk.gov.communities.delta.auth.security.DELTA_AD_LDAP_SERVICE_USERS_AUTH_NAME
import uk.gov.communities.delta.auth.security.DeltaLdapPrincipal
import uk.gov.communities.delta.auth.services.OAuthSession

val initMDC = createApplicationPlugin("InitMDCForCall") {
    on(BeforeMonitoring) { call, proceed ->
        val remoteAddress = call.request.origin.remoteAddress
        val spanContext = Span.current().spanContext
        if (!spanContext.isValid) throw Exception("Invalid span context")
        val endpoint = "${call.request.httpMethod.value} ${call.request.path()}"

        val map = mapOf(
            "endpoint" to endpoint,
            "IPAddress" to remoteAddress,
            "requestId" to call.callId!!,
            "XRayTraceId" to spanContext.traceId,
        )

        withContext(MDCContext(map)) {
            proceed()
        }

        MDC.clear()
    }
}

val addServiceUserUsernameToMDC = createRouteScopedPlugin("AddUsernameToMdc") {
    on(BeforeCall) { call, proceed ->
        val principal = call.principal<DeltaLdapPrincipal>(DELTA_AD_LDAP_SERVICE_USERS_AUTH_NAME) ?: return@on proceed()
        val mdcContextMap = MDC.getCopyOfContextMap() ?: mutableMapOf()
        mdcContextMap["username"] = principal.username
        Span.current().setAttribute("delta.username", principal.username)
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
        Span.current().setAttribute("delta.clientId", principal.client.clientId)
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
        mdcContextMap["userGUID"] = session.userGUID.toString()
        mdcContextMap["oauthSession"] = session.id.toString()
        mdcContextMap["trace"] = session.traceId
        val span = Span.current()
        span.setAttribute("delta.username", session.userCn ?: "")
        span.setAttribute("enduser.id", session.userGUID.toString())
        span.setAttribute("delta.oauthSession", session.id.toString())
        span.setAttribute("delta.trace", session.traceId)
        withContext(MDCContext(mdcContextMap)) {
            proceed()
        }
    }
}
