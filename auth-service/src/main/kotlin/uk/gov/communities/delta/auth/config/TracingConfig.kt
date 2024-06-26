package uk.gov.communities.delta.auth.config

import org.slf4j.spi.LoggingEventBuilder

class TracingConfig(val prefix: String?) {
    companion object {
        fun fromEnv(): TracingConfig {
            if (Env.getEnv("RUN_TASK")?.isNotEmpty() == true) {
                return TracingConfig(null) // Disable telemetry in scheduled jobs
            }
            val prefix = Env.getEnv("AUTH_TELEMETRY_PREFIX")
            return TracingConfig(if (prefix.isNullOrEmpty()) null else prefix)
        }
    }

    val enabled = prefix != null
    val serviceName = if (prefix != null) "$prefix-auth-service" else null

    fun log(logger: LoggingEventBuilder) {
        logger
            .addKeyValue("TracingEnabled", enabled).addKeyValue("TelemetryServiceName", serviceName)
            .log("Tracing config")
    }
}
