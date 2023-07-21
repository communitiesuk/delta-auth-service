package uk.gov.communities.delta.auth

import io.ktor.server.application.*
import io.ktor.server.engine.*
import io.ktor.server.netty.*
import uk.gov.communities.delta.auth.plugins.configureMonitoring
import uk.gov.communities.delta.auth.plugins.configureSerialization
import uk.gov.communities.delta.auth.plugins.configureStatusPages
import uk.gov.communities.delta.auth.plugins.configureTemplating
import uk.gov.communities.delta.auth.security.configureSecurity

fun main() {
    Injection.startupInitFromEnvironment()
    val keyStore = SelfSignedSSLCertKeystore.getKeystore()
    val environment = applicationEngineEnvironment {
        connector {
            port = 8088
        }
        sslConnector(keyStore = keyStore,
            keyAlias = "auth-service",
            keyStorePassword = { SelfSignedSSLCertKeystore.keyStorePassword.toCharArray() },
            privateKeyPassword = { SelfSignedSSLCertKeystore.keyStorePassword.toCharArray() }) {
            port = 8443
        }
        module(Application::module)
    }
    embeddedServer(Netty, environment).start(wait = true)
}

fun Application.module() {
    Injection.instance.logConfig(log)

    if (developmentMode) {
        // Skip database connection and migrations in development mode and in tests
        log.info("Skipping database initialisation, will happen on first connection")
    } else {
        Injection.instance.dbPool.eagerInit()
    }

    configureSecurity(Injection.instance)
    configureMonitoring()
    configureSerialization()
    configureTemplating(developmentMode)
    configureRouting(Injection.instance)
    configureStatusPages(Injection.instance.deltaConfig.deltaWebsiteUrl)
}
