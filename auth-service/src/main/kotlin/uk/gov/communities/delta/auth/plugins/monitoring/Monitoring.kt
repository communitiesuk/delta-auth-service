package uk.gov.communities.delta.auth.plugins.monitoring

import io.ktor.server.application.*
import io.ktor.server.metrics.micrometer.*
import io.ktor.server.plugins.callid.*
import io.micrometer.core.instrument.MeterRegistry
import io.opentelemetry.api.OpenTelemetry
import io.opentelemetry.instrumentation.api.config.IncludeExclude
import io.opentelemetry.instrumentation.ktor.v2_0.KtorServerTelemetry

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
    install(KtorServerTelemetry) {
        setOpenTelemetry(openTelemetry)
        requestHeaders(IncludeExclude.builder().setIncluded("X-Amz-Cf-Id").build())
    }
}
