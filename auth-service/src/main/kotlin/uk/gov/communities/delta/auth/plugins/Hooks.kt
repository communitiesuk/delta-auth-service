package uk.gov.communities.delta.auth.plugins

import io.ktor.server.application.*
import io.ktor.server.response.*
import io.ktor.util.*
import io.ktor.util.pipeline.*

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

internal object NewPhaseBeforeMonitoring : Hook<suspend (ApplicationCall, suspend () -> Unit) -> Unit> {
    override fun install(
        pipeline: ApplicationCallPipeline,
        handler: suspend (ApplicationCall, suspend () -> Unit) -> Unit,
    ) {
        val phase = PipelinePhase("BeforeOpenTelemetry")
        pipeline.insertPhaseBefore(ApplicationCallPipeline.Monitoring, phase)

        pipeline.intercept(phase) {
            handler(call, ::proceed)
        }
    }
}

internal object MonitoringHook : Hook<suspend (ApplicationCall, suspend () -> Unit) -> Unit> {
    override fun install(
        pipeline: ApplicationCallPipeline,
        handler: suspend (ApplicationCall, suspend () -> Unit) -> Unit,
    ) {
        pipeline.intercept(ApplicationCallPipeline.Monitoring) {
            handler(call, ::proceed)
        }
    }
}

internal object ResponseSent : Hook<suspend (ApplicationCall) -> Unit> {
    override fun install(pipeline: ApplicationCallPipeline, handler: suspend (ApplicationCall) -> Unit) {
        pipeline.sendPipeline.intercept(ApplicationSendPipeline.Engine) {
            // This phase gets triggered twice by Status Pages, make sure tis only runs once
            if (call.attributes.contains(responseSentMarker)) return@intercept

            call.attributes.put(responseSentMarker, Unit)
            proceed()
            handler(call)
        }
    }
}

private val responseSentMarker = AttributeKey<Unit>("ResponseSentTriggered")
