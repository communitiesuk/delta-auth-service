package uk.gov.communities.delta.helper

import io.opentelemetry.api.OpenTelemetry
import io.opentelemetry.api.common.AttributeKey
import io.opentelemetry.api.trace.propagation.W3CTraceContextPropagator
import io.opentelemetry.context.propagation.ContextPropagators
import io.opentelemetry.context.propagation.TextMapPropagator
import io.opentelemetry.contrib.awsxray.AwsXrayIdGenerator
import io.opentelemetry.contrib.awsxray.propagator.AwsXrayPropagator
import io.opentelemetry.exporter.logging.LoggingSpanExporter
import io.opentelemetry.sdk.OpenTelemetrySdk
import io.opentelemetry.sdk.resources.Resource
import io.opentelemetry.sdk.trace.SdkTracerProvider
import io.opentelemetry.sdk.trace.export.SimpleSpanProcessor
import io.opentelemetry.sdk.trace.samplers.Sampler
import uk.gov.communities.delta.auth.plugins.NoHealthChecksSampler

val testOpenTelemetry: OpenTelemetry by lazy {
    val resource = Resource.getDefault().toBuilder()
        .put(AttributeKey.stringKey("service.name"), "auth-unit-tests")
        .build()

    OpenTelemetrySdk.builder()
        // Propagate the X-Ray trace header
        .setPropagators(
            ContextPropagators.create(
                TextMapPropagator.composite(
                    W3CTraceContextPropagator.getInstance(), AwsXrayPropagator.getInstance()
                )
            )
        ).setTracerProvider(
            SdkTracerProvider.builder()
                .setResource(resource)
                .addSpanProcessor(
                    SimpleSpanProcessor.builder(LoggingSpanExporter.create()).build()
                )
                .setSampler(Sampler.parentBased(NoHealthChecksSampler()))
                // Generate X-Ray compliant span IDs
                .setIdGenerator(AwsXrayIdGenerator.getInstance())
                .build()
        ).build()
}
