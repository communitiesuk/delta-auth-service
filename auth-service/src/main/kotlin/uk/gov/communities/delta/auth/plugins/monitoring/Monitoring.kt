package uk.gov.communities.delta.auth.plugins.monitoring

import io.ktor.server.application.*
import io.ktor.server.metrics.micrometer.*
import io.ktor.server.plugins.callid.*
import io.micrometer.core.instrument.MeterRegistry
import io.opentelemetry.api.OpenTelemetry
import io.opentelemetry.api.trace.Span
import io.opentelemetry.context.Context
import io.opentelemetry.extension.kotlin.asContextElement
import io.opentelemetry.instrumentation.ktor.v2_0.server.KtorServerTracing
import kotlinx.coroutines.withContext
import uk.gov.communities.delta.auth.plugins.NewPhaseBeforeMonitoring

fun Application.configureMonitoring(meterRegistry: MeterRegistry, openTelemetry: OpenTelemetry) {
    install(initMDC)
    install(CustomCallLogging)
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
    }
    // Install this before KtorServerTracing so it runs first
    install(checkOpenTelemetrySpanContext)
    install(KtorServerTracing) {
        setOpenTelemetry(openTelemetry)
        capturedRequestHeaders("X-Amz-Cf-Id")
    }
}

val checkOpenTelemetrySpanContext = createApplicationPlugin("CheckOTELContext") {
    on(NewPhaseBeforeMonitoring) { call, proceed ->
        if (Context.current() !== Context.root()) {
            val spanContext = Span.current().spanContext
            call.application.log.debug(
                "OpenTelemetry context is set before the request has started and will be cleared from this thread. Request id {}, Span id {}, trace id {}",
                call.callId, spanContext.spanId, spanContext.traceId
            )
            Context.root().makeCurrent()
        }
        /*
         * The current span context doesn't always get cleared from ThreadLocal storage outside the withContext block.
         * This can cause issues as KtorServerTracing uses the context from thread storage as a parent span.
         * It's not completely clear whether this is a bug or just a weak guarantee of ThreadContextElement,
         * but wrapping the request in the empty "root" context resolves it.
         */
        withContext(Context.root().asContextElement()) {
            proceed()
        }
        if (Context.current() !== Context.root())
            Context.root().makeCurrent()
    }
}
