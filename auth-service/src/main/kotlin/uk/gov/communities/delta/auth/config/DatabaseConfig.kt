package uk.gov.communities.delta.auth.config

import org.slf4j.spi.LoggingEventBuilder

data class DatabaseConfig(
    val url: String,
    val user: String,
    val password: String,
) {
    companion object {
        fun fromEnv() =  DatabaseConfig(
            url = Env.getEnvOrDevFallback("DATABASE_URL", "jdbc:postgresql://localhost:5438/postgres"),
            user = Env.getEnvOrDevFallback("DATABASE_USER", "postgres"),
            password = Env.getEnvOrDevFallback("DATABASE_PASSWORD", "postgres"),
        )
    }

    fun log(logger: LoggingEventBuilder) {
        logger
            .addKeyValue("DATABASE_URL", url)
            .addKeyValue("DATABASE_USER", user)
            .log("Database config")
    }
}
