package uk.gov.communities.delta.auth.config

import org.slf4j.spi.LoggingEventBuilder

class AuthServiceConfig(val serviceUrl: String, val metricsNamespace: String?) {
    companion object {
        fun fromEnv() = AuthServiceConfig(
            serviceUrl = Env.getRequiredOrDevFallback("SERVICE_URL", "http://localhost:8088"),
            metricsNamespace = Env.getRequiredOrNullDevFallback("AUTH_METRICS_NAMESPACE")
        )
    }

    fun log(logger: LoggingEventBuilder) {
        logger.addKeyValue("SERVICE_URL", serviceUrl).addKeyValue("AUTH_METRICS_NAMESPACE", metricsNamespace)
            .log("Service config")
    }
}
