package uk.gov.communities.delta.auth

import io.ktor.server.application.*
import io.ktor.server.engine.*
import io.ktor.server.netty.*
import uk.gov.communities.delta.auth.plugins.configureMonitoring
import uk.gov.communities.delta.auth.plugins.configureSerialization
import uk.gov.communities.delta.auth.security.configureSecurity

fun main() {
    val keyStore = SelfSignedSSLCertKeystore.getKeystore()
    val environment = applicationEngineEnvironment {
        connector {
            port = 8080
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
    configureSecurity()
    configureMonitoring()
    configureSerialization()
    configureRouting()
}
