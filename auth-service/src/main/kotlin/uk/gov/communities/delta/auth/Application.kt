package uk.gov.communities.delta.auth

import io.ktor.server.application.*
import io.ktor.server.engine.*
import io.ktor.server.netty.*
import uk.gov.communities.delta.auth.plugins.configureSerialization
import uk.gov.communities.delta.auth.plugins.configureStatusPages
import uk.gov.communities.delta.auth.plugins.configureTemplating
import uk.gov.communities.delta.auth.plugins.monitoring.configureMonitoring
import uk.gov.communities.delta.auth.security.configureRateLimiting
import uk.gov.communities.delta.auth.security.configureSecurity

fun main() {
    val keyStore = SelfSignedSSLCertKeystore.getKeystore()
    embeddedServer(Netty, configure = {
        connector {
            port = 8088
        }
        sslConnector(keyStore = keyStore,
            keyAlias = "auth-service",
            keyStorePassword = { SelfSignedSSLCertKeystore.KEY_STORE_PASSWORD.toCharArray() },
            privateKeyPassword = { SelfSignedSSLCertKeystore.KEY_STORE_PASSWORD.toCharArray() }) {
            port = 8443
        }
    }) {
        Injection.startupInitFromEnvironment().registerShutdownHook()
        appModule()
    }.start(wait = true)
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
        injection.setPasswordRateLimitCounter,
        injection.resetPasswordRateLimitCounter,
        injection.forgotPasswordRateLimitCounter,
    )
    configureSecurity(injection)
    configureMonitoring(injection.meterRegistry, injection.openTelemetry, injection.tracingConfig)
    configureSerialization()
    configureTemplating(developmentMode)
    configureRouting(injection)
    configureStatusPages(injection.deltaConfig.deltaWebsiteUrl, injection.azureADSSOConfig, injection.deltaConfig)
}
