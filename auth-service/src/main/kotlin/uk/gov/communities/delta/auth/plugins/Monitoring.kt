package uk.gov.communities.delta.auth.plugins

import io.ktor.server.application.*
import io.ktor.server.auth.*
import io.ktor.server.metrics.micrometer.*
import io.ktor.server.plugins.*
import io.ktor.server.plugins.callid.*
import io.ktor.server.plugins.callloging.*
import io.ktor.server.request.*
import io.micrometer.core.instrument.MeterRegistry
import io.micrometer.core.instrument.config.MeterFilter
import io.opentelemetry.api.OpenTelemetry
import io.opentelemetry.api.common.AttributeKey
import io.opentelemetry.api.common.Attributes
import io.opentelemetry.api.trace.Span
import io.opentelemetry.api.trace.SpanBuilder
import io.opentelemetry.api.trace.SpanKind
import io.opentelemetry.api.trace.propagation.W3CTraceContextPropagator
import io.opentelemetry.context.Context
import io.opentelemetry.context.propagation.ContextPropagators
import io.opentelemetry.context.propagation.TextMapPropagator
import io.opentelemetry.contrib.awsxray.AwsXrayIdGenerator
import io.opentelemetry.contrib.awsxray.propagator.AwsXrayPropagator
import io.opentelemetry.exporter.otlp.trace.OtlpGrpcSpanExporter
import io.opentelemetry.instrumentation.ktor.v2_0.server.KtorServerTracing
import io.opentelemetry.sdk.OpenTelemetrySdk
import io.opentelemetry.sdk.resources.Resource
import io.opentelemetry.sdk.trace.SdkTracerProvider
import io.opentelemetry.sdk.trace.data.LinkData
import io.opentelemetry.sdk.trace.export.BatchSpanProcessor
import io.opentelemetry.sdk.trace.samplers.Sampler
import io.opentelemetry.sdk.trace.samplers.SamplingResult
import kotlinx.coroutines.slf4j.MDCContext
import kotlinx.coroutines.withContext
import org.slf4j.MDC
import org.slf4j.event.Level
import uk.gov.communities.delta.auth.config.TracingConfig
import uk.gov.communities.delta.auth.security.CLIENT_HEADER_AUTH_NAME
import uk.gov.communities.delta.auth.security.ClientPrincipal
import uk.gov.communities.delta.auth.security.DELTA_AD_LDAP_SERVICE_USERS_AUTH_NAME
import uk.gov.communities.delta.auth.security.DeltaLdapPrincipal
import uk.gov.communities.delta.auth.services.OAuthSession
import kotlin.collections.set

fun Application.configureMonitoring(meterRegistry: MeterRegistry, openTelemetry: OpenTelemetry) {
    // TODO At some point we should replace this, we want structured logs
    // and to clear the MDC before each request
    install(CallLogging) {
        level = Level.INFO
        callIdMdc("requestId")
        filter { it.request.path() != "/health" }
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
            .meterFilter(MeterFilter.acceptNameStartsWith("resetPassword."))
            .meterFilter(MeterFilter.acceptNameStartsWith("forgotPassword."))
            .meterFilter(MeterFilter.acceptNameStartsWith("tasks."))
            .meterFilter(MeterFilter.deny()) // Currently don't want any other metrics
    }
    install(KtorServerTracing) {
        setOpenTelemetry(openTelemetry)
        capturedRequestHeaders("X-Amz-Cf-Id")
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

fun initOpenTelemetry(tracingConfig: TracingConfig): OpenTelemetry {
    val resource = Resource.getDefault().toBuilder()
        .put(AttributeKey.stringKey("service.name"), tracingConfig.serviceName ?: "DISABLED")
        .build()

    var openTelemetryBuilder = OpenTelemetrySdk.builder()
        // Propagate the X-Ray trace header
        .setPropagators(
            ContextPropagators.create(
                TextMapPropagator.composite(
                    W3CTraceContextPropagator.getInstance(), AwsXrayPropagator.getInstance()
                )
            )
        )

    if (tracingConfig.enabled) {
        openTelemetryBuilder = openTelemetryBuilder.setTracerProvider(
            SdkTracerProvider.builder()
                .setResource(resource)
                .addSpanProcessor(
                    BatchSpanProcessor.builder(OtlpGrpcSpanExporter.getDefault()).build()
                )
                .setSampler(Sampler.parentBased(NoHealthChecksSampler()))
                // Generate X-Ray compliant span IDs
                .setIdGenerator(AwsXrayIdGenerator.getInstance())
                .build()
        )
    }

    return openTelemetryBuilder.buildAndRegisterGlobal()
}

class NoHealthChecksSampler : Sampler {
    private val pathKey = AttributeKey.stringKey("url.path")

    override fun shouldSample(
        parentContext: Context,
        traceId: String,
        name: String,
        spanKind: SpanKind,
        attributes: Attributes,
        parentLinks: MutableList<LinkData>
    ): SamplingResult {
        return if (attributes.get(pathKey) == "/health") SamplingResult.drop() else SamplingResult.recordAndSample()
    }

    override fun getDescription(): String {
        return "Custom sampler that excludes requests to /health"
    }
}

typealias SpanFactory = (String) -> SpanBuilder
