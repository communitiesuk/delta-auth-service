package uk.gov.communities.delta

import io.ktor.client.request.*
import io.ktor.client.statement.*
import io.ktor.server.testing.*
import kotlin.test.*
import io.ktor.http.*
import uk.gov.communities.delta.auth.configureRouting
import uk.gov.communities.delta.auth.plugins.configureSerialization
import uk.gov.communities.delta.auth.security.configureSecurity

class ApplicationTest {
    @Test
    fun testRoot() = testApplication {
        application {
            configureSecurity()
            configureSerialization()
            configureRouting()
        }
        client.get("/").apply {
            assertEquals(HttpStatusCode.OK, status)
            assertEquals("Hello World!", bodyAsText())
        }
    }
}
