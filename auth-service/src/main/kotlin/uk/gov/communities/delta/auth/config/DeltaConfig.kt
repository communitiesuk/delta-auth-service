package uk.gov.communities.delta.auth.config

import org.slf4j.spi.LoggingEventBuilder

class DeltaConfig(
    val deltaWebsiteUrl: String,
    val rateLimit: Int,
    val masterStoreBaseNoAuth: String,
) {
    companion object {
        fun fromEnv() = DeltaConfig(
            deltaWebsiteUrl = Env.getRequiredOrDevFallback("DELTA_WEBSITE_URL", "http://localhost:8080"),
            rateLimit = Env.getRequiredOrDevFallback("AUTH_RATE_LIMIT", "100").toInt(),
            masterStoreBaseNoAuth = Env.getRequiredOrDevFallback(
                "DELTA_MARKLOGIC_LDAP_AUTH_APP_SERVICE",
                "http://localhost:8030/"
            ),
        )

        const val DATAMART_DELTA_USER = LDAPConfig.DATAMART_DELTA_PREFIX + "user"
        const val DATAMART_DELTA_REPORT_USERS = LDAPConfig.DATAMART_DELTA_PREFIX + "report-users"
        const val DATAMART_DELTA_ADMIN = LDAPConfig.DATAMART_DELTA_PREFIX + "admin"
        const val DATAMART_DELTA_INTERNAL_USER = LDAPConfig.DATAMART_DELTA_PREFIX + "user-dclg"
    }

    fun log(logger: LoggingEventBuilder) {
        logger.addKeyValue("DELTA_WEBSITE_URL", deltaWebsiteUrl).addKeyValue("AUTH_RATE_LIMIT", rateLimit)
            .log("Delta config")
    }
}
