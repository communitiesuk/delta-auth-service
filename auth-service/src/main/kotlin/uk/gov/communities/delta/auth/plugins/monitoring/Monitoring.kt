package uk.gov.communities.delta.auth.plugins.monitoring

import io.ktor.server.application.*
import io.ktor.server.metrics.micrometer.*
import io.ktor.server.plugins.callid.*
import io.micrometer.core.instrument.MeterRegistry
import io.micrometer.core.instrument.config.MeterFilter
import io.opentelemetry.api.OpenTelemetry
import io.opentelemetry.instrumentation.ktor.v2_0.server.KtorServerTracing

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
