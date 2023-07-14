package uk.gov.communities.delta.auth.config

import org.slf4j.spi.LoggingEventBuilder

class DeltaConfig {
    companion object {
        val DELTA_WEBSITE_URL = System.getenv("DELTA_WEBSITE_URL") ?: "http://localhost:8080"
        const val REQUIRED_GROUP_CN = "datamart-delta-user"

        fun log(logger: LoggingEventBuilder) {
            logger
                .addKeyValue("DELTA_WEBSITE_URL", DELTA_WEBSITE_URL)
                .log("Delta config")
        }
    }
}
