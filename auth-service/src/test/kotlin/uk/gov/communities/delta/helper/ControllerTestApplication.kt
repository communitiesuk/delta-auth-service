package uk.gov.communities.delta.helper

import io.ktor.server.engine.*
import io.ktor.server.testing.*
import io.ktor.util.pipeline.*

fun controllerTestApplication(block: TestApplicationBuilder.() -> Unit): TestApplication = TestApplication {
    application {
        val testEngine = engine as TestApplicationEngine
        val phase = PipelinePhase("PropagateControllerException")
        // Run the test interceptor before Ktor 3's engine fallback can turn its rethrow into a 500.
        testEngine.pipeline.insertPhaseBefore(EnginePipeline.Before, phase)
        testEngine.pipeline.intercept(phase) {
            testEngine.callInterceptor.invoke(this, Unit)
            finish()
        }
    }
    block()
}
