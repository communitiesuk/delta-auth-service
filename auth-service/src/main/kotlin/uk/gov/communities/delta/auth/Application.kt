package uk.gov.communities.delta.auth

import io.ktor.server.application.*
import io.ktor.server.engine.*
import io.ktor.server.netty.*
import uk.gov.communities.delta.auth.plugins.configureMonitoring
import uk.gov.communities.delta.auth.plugins.configureSerialization
import uk.gov.communities.delta.auth.plugins.configureStatusPages
import uk.gov.communities.delta.auth.plugins.configureTemplating
import uk.gov.communities.delta.auth.security.configureRateLimiting
import uk.gov.communities.delta.auth.security.configureSecurity

fun main() {
    val keyStore = SelfSignedSSLCertKeystore.getKeystore()
    val environment = applicationEngineEnvironment {
        connector {
            port = 8088
        }
        sslConnector(keyStore = keyStore,
            keyAlias = "auth-service",
            keyStorePassword = { SelfSignedSSLCertKeystore.KEY_STORE_PASSWORD.toCharArray() },
            privateKeyPassword = { SelfSignedSSLCertKeystore.KEY_STORE_PASSWORD.toCharArray() }) {
            port = 8443
        }
        module {
            Injection.startupInitFromEnvironment().registerShutdownHook()
            appModule()
        }
    }
    embeddedServer(Netty, environment).start(wait = true)
}

fun Application.appModule() {
    val injection = Injection.instance
    injection.logConfig(log)

    if (developmentMode) {
        // Skip database connection and migrations in development mode and in tests
        log.info("Skipping database initialisation, will happen on first connection")
    } else {
        injection.dbPool.eagerInit()
    }

    configureRateLimiting(
        injection.deltaConfig.rateLimit,
        injection.loginRateLimitCounter,
        injection.registrationRateLimitCounter,
        injection.setPasswordRateLimitCounter
    )
    configureSecurity(injection)
    configureMonitoring(injection.meterRegistry)
    configureSerialization()
    configureTemplating(developmentMode)
    configureRouting(injection)
    configureStatusPages(injection.deltaConfig.deltaWebsiteUrl, injection.azureADSSOConfig, injection.deltaConfig)
}
