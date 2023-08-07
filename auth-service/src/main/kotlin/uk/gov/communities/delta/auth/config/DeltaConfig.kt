package uk.gov.communities.delta.auth.config

import org.slf4j.spi.LoggingEventBuilder

class DeltaConfig(
    val deltaWebsiteUrl: String,
    val requiredGroupCn: String,
    val rateLimit: Int,
) {
    companion object {
        fun fromEnv() = DeltaConfig(
            deltaWebsiteUrl = Env.getRequiredOrDevFallback("DELTA_WEBSITE_URL", "http://localhost:8080"),
            requiredGroupCn = "datamart-delta-user",
            rateLimit = Env.getRequiredOrDevFallback("AUTH_RATE_LIMIT", "10").toInt()
        )
    }

    fun log(logger: LoggingEventBuilder) {
        logger.addKeyValue("DELTA_WEBSITE_URL", deltaWebsiteUrl).addKeyValue("AUTH_RATE_LIMIT", rateLimit).log("Delta config")
    }
}
