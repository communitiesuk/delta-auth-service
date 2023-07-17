package uk.gov.communities.delta.dbintegration

import uk.gov.communities.delta.auth.config.DatabaseConfig
import uk.gov.communities.delta.auth.services.DbPool
import java.sql.DriverManager

val testDbPool: DbPool by lazy {
    val config = DatabaseConfig.fromEnv()
    DriverManager.getConnection(
        "jdbc:postgresql://localhost:5438/",
        config.user,
        config.password,
    ).use {
        it.createStatement().execute("DROP DATABASE IF EXISTS test; CREATE DATABASE test")
    }
    val pool = DbPool(config.copy(url = "jdbc:postgresql://localhost:5438/test"))
    pool.eagerInit()
    pool
}
