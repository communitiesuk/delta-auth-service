package uk.gov.communities.delta.auth.plugins.monitoring

import io.opentelemetry.api.OpenTelemetry
import io.opentelemetry.api.common.AttributeKey
import io.opentelemetry.api.common.Attributes
import io.opentelemetry.api.trace.SpanBuilder
import io.opentelemetry.api.trace.SpanKind
import io.opentelemetry.api.trace.propagation.W3CTraceContextPropagator
import io.opentelemetry.context.Context
import io.opentelemetry.context.propagation.ContextPropagators
import io.opentelemetry.context.propagation.TextMapPropagator
import io.opentelemetry.contrib.awsxray.AwsXrayIdGenerator
import io.opentelemetry.contrib.awsxray.propagator.AwsXrayPropagator
import io.opentelemetry.exporter.otlp.trace.OtlpGrpcSpanExporter
import io.opentelemetry.sdk.OpenTelemetrySdk
import io.opentelemetry.sdk.resources.Resource
import io.opentelemetry.sdk.trace.SdkTracerProvider
import io.opentelemetry.sdk.trace.data.LinkData
import io.opentelemetry.sdk.trace.export.BatchSpanProcessor
import io.opentelemetry.sdk.trace.samplers.Sampler
import io.opentelemetry.sdk.trace.samplers.SamplingResult
import uk.gov.communities.delta.auth.config.TracingConfig

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
