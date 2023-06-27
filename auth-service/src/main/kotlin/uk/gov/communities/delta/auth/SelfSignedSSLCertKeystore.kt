package uk.gov.communities.delta.auth

import io.ktor.network.tls.certificates.*
import org.slf4j.LoggerFactory
import java.io.File
import java.security.KeyStore

/*
* We deploy behind an AWS ALB which doesn't validate SSL certificates anyway
* so generate a self-signed certificate on startup
*/
class SelfSignedSSLCertKeystore {
    companion object {
        const val keyStorePassword = ""
        private val logger = LoggerFactory.getLogger(SelfSignedSSLCertKeystore::class.java)

        fun getKeystore(): KeyStore {
            val keyStoreFile = File("sslKeystore.jks")
            if (keyStoreFile.exists()) {
                return KeyStore.getInstance(keyStoreFile, keyStorePassword.toCharArray())
            }
            logger.info("Generating a new SSL Keystore")
            val keyStore = buildKeyStore {
                certificate("auth-service") {
                    password = keyStorePassword
                    domains = listOf("localhost")
                }
            }
            keyStore.saveToFile(keyStoreFile, keyStorePassword)
            return keyStore
        }
    }
}
