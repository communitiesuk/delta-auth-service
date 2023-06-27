package uk.gov.communities.delta.auth.plugins

import io.ktor.server.plugins.callloging.*
import org.slf4j.event.*
import io.ktor.server.request.*
import io.ktor.http.*
import io.ktor.server.plugins.callid.*
import io.ktor.server.application.*

fun Application.configureMonitoring() {
    install(CallLogging) {
        level = Level.INFO
        callIdMdc("requestId")
    }
    install(CallId) {
        header("X-Amz-Cf-Id")
        verify { callId: String ->
            callId.isNotEmpty()
        }
    }
}
