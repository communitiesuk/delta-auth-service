package uk.gov.communities.delta.auth

import io.ktor.server.application.*
import io.ktor.server.engine.*
import io.ktor.server.netty.*
import uk.gov.communities.delta.auth.config.DatabaseConfig
import uk.gov.communities.delta.auth.config.DeltaConfig
import uk.gov.communities.delta.auth.config.LDAPConfig
import uk.gov.communities.delta.auth.plugins.configureMonitoring
import uk.gov.communities.delta.auth.plugins.configureSerialization
import uk.gov.communities.delta.auth.plugins.configureTemplating
import uk.gov.communities.delta.auth.security.configureSecurity

fun main() {
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
    LDAPConfig.log(log.atInfo())
    DeltaConfig.log(log.atInfo())
    DatabaseConfig.Config.log(log.atInfo())
    if (developmentMode) {
        log.info("Skipping database initialisation, will happen on first connection")
    } else {
        Injection.databaseConnectionService.eagerInit()
    }

    configureSecurity()
    configureMonitoring()
    configureSerialization()
    configureTemplating(developmentMode)
    configureRouting()
}
