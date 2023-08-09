package uk.gov.communities.delta.auth.config

import org.slf4j.spi.LoggingEventBuilder

class AuthServiceConfig(val serviceUrl: String) {
    companion object {
        fun fromEnv() = AuthServiceConfig(
            serviceUrl = Env.getRequiredOrDevFallback("SERVICE_URL", "http://localhost:8088"),
        )
    }

    fun log(logger: LoggingEventBuilder) {
        logger.addKeyValue("SERVICE_URL", serviceUrl).log("Service config")
    }
}
