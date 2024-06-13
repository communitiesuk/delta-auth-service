package uk.gov.communities.delta.auth.repositories

import com.zaxxer.hikari.HikariConfig
import com.zaxxer.hikari.HikariDataSource
import io.ktor.utils.io.core.*
import io.opentelemetry.api.OpenTelemetry
import io.opentelemetry.instrumentation.jdbc.datasource.JdbcTelemetry
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.flywaydb.core.Flyway
import org.jetbrains.annotations.Blocking
import org.slf4j.LoggerFactory
import uk.gov.communities.delta.auth.config.DatabaseConfig
import uk.gov.communities.delta.auth.utils.timed
import java.sql.Connection
import javax.sql.DataSource
import kotlin.contracts.ExperimentalContracts
import kotlin.contracts.InvocationKind
import kotlin.contracts.contract
import kotlin.time.Duration.Companion.seconds

class DbPool(private val config: DatabaseConfig, private val openTelemetry: OpenTelemetry?) : Closeable {
    private val logger = LoggerFactory.getLogger(javaClass)

    private val connectionPoolDelegate = lazy(::createPoolAndMigrate)
    private val connectionPool: DataSource by connectionPoolDelegate
    private var unwrappedConnectionPool: HikariDataSource? = null

    @Blocking
    fun connection(): Connection {
        return connectionPool.connection
    }

    @Blocking
    @OptIn(ExperimentalContracts::class)
    fun <R> useConnectionBlocking(action: String, block: (Connection) -> R): R {
        contract {
            callsInPlace(block, InvocationKind.EXACTLY_ONCE)
        }
        return logger.timed(action) {
            connection().use(block)
        }
    }

    @OptIn(ExperimentalContracts::class)
    suspend fun <R> useConnectionNonBlocking(action: String, block: (Connection) -> R): R {
        contract {
            callsInPlace(block, InvocationKind.EXACTLY_ONCE)
        }
        return withContext(Dispatchers.IO) {
            logger.timed(action) {
                connection().use(block)
            }
        }
    }

    fun eagerInit() {
        if (connectionPoolDelegate.isInitialized()) {
            throw Exception("Already initialised!")
        }
        connectionPoolDelegate.value
    }

    private fun createPoolAndMigrate(): DataSource {
        val startTime = System.currentTimeMillis()
        val pool = createHikariDataSource()
        Flyway.configure().dataSource(pool).load().migrate()
        logger.info("Database migrated and ready in {} seconds", (System.currentTimeMillis() - startTime) / 1000.0)
        unwrappedConnectionPool = pool
        return if (openTelemetry == null) pool else JdbcTelemetry.create(openTelemetry).wrap(pool)
    }

    private fun createHikariDataSource() = HikariDataSource(HikariConfig().apply {
        driverClassName = "org.postgresql.Driver"
        username = config.user
        password = config.password
        jdbcUrl = config.url
        maximumPoolSize = 10
        minimumIdle = 2
        isAutoCommit = false
        transactionIsolation = "TRANSACTION_REPEATABLE_READ"
        connectionTimeout = 20.seconds.inWholeMilliseconds
        validate()
    })

    override fun close() {
        unwrappedConnectionPool?.close()
    }
}

fun main() {
    DbPool(DatabaseConfig.fromEnv(), null).eagerInit()
}
