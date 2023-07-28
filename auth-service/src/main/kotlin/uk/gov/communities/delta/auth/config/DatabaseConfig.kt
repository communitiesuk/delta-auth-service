package uk.gov.communities.delta.auth.config

import org.slf4j.spi.LoggingEventBuilder

data class DatabaseConfig(
    val url: String,
    val user: String,
    val password: String,
) {
    companion object {
        fun fromEnv() =  DatabaseConfig(
            url = System.getenv("DATABASE_URL") ?: "jdbc:postgresql://localhost:5438/postgres",
            user = System.getenv("DATABASE_USER") ?: "postgres",
            password = System.getenv("DATABASE_PASSWORD") ?: "postgres",
        )
    }

    fun log(logger: LoggingEventBuilder) {
        logger
            .addKeyValue("DATABASE_URL", url)
            .addKeyValue("DATABASE_USER", user)
            .log("Database config")
    }
}
