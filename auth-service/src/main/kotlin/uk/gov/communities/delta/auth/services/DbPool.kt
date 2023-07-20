package uk.gov.communities.delta.auth.services

import com.zaxxer.hikari.HikariConfig
import com.zaxxer.hikari.HikariDataSource
import org.flywaydb.core.Flyway
import org.slf4j.LoggerFactory
import uk.gov.communities.delta.auth.config.DatabaseConfig
import java.sql.Connection
import kotlin.contracts.ExperimentalContracts
import kotlin.contracts.InvocationKind
import kotlin.contracts.contract

class DbPool(private val config: DatabaseConfig) {
    private val logger = LoggerFactory.getLogger(javaClass)

    private val connectionPoolDelegate = lazy(::createPoolAndMigrate)
    private val connectionPool: HikariDataSource by connectionPoolDelegate

    fun connection(): Connection {
        return connectionPool.connection
    }

    @OptIn(ExperimentalContracts::class)
    inline fun <R> useConnection(block: (Connection) -> R): R {
        contract {
            callsInPlace(block, InvocationKind.EXACTLY_ONCE)
        }
        return connection().use(block)
    }

    fun eagerInit() {
        if (connectionPoolDelegate.isInitialized()) {
            throw Exception("Already initialised!")
        }
        connectionPoolDelegate.value
    }

    private fun createPoolAndMigrate(): HikariDataSource {
        val startTime = System.currentTimeMillis()
        val pool = createHikariDataSource()
        Flyway.configure().dataSource(pool).load().migrate()
        logger.info("Database migrated and ready in {} seconds", (System.currentTimeMillis() - startTime) / 1000.0)
        return pool
    }

    private fun createHikariDataSource() = HikariDataSource(HikariConfig().apply {
        driverClassName = "org.postgresql.Driver"
        username = config.user
        password = config.password
        jdbcUrl = config.url
        maximumPoolSize = 10
        isAutoCommit = false
        transactionIsolation = "TRANSACTION_REPEATABLE_READ"
        validate()
    })
}
