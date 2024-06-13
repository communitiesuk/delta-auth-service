package uk.gov.communities.delta.controllers

import io.ktor.client.request.*
import io.ktor.client.statement.*
import io.ktor.server.routing.*
import io.ktor.server.testing.*
import io.ktor.test.dispatcher.*
import uk.gov.communities.delta.auth.config.AzureADSSOConfig
import uk.gov.communities.delta.auth.config.DeltaConfig
import uk.gov.communities.delta.auth.plugins.UserVisibleServerError
import uk.gov.communities.delta.auth.plugins.configureStatusPages
import uk.gov.communities.delta.auth.plugins.configureTemplating
import kotlin.test.Test
import kotlin.test.assertTrue

class StatusPagesTest {
    @Test
    fun testUserVisibleError() = testSuspend {
        val app = TestApplication {
            application {
                configureTemplating(false)
                configureStatusPages("http://delta", AzureADSSOConfig(emptyList()), DeltaConfig("url", 10, "", "localhost"))
                routing {
                    get("/userVisibleError") {
                        throw UserVisibleServerError("code", "internal message", "user message")
                    }
                }
            }
        }
        app.client.get("/userVisibleError").apply {
            assertTrue(bodyAsText().contains("user message"))
        }
    }
}
