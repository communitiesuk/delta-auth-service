package uk.gov.communities.delta

import io.ktor.client.request.*
import io.ktor.client.statement.*
import io.ktor.http.*
import io.ktor.server.testing.*
import io.ktor.test.dispatcher.*
import org.junit.BeforeClass
import uk.gov.communities.delta.auth.Injection
import uk.gov.communities.delta.auth.config.*
import uk.gov.communities.delta.auth.module
import kotlin.test.Test
import kotlin.test.assertEquals

/*
 * Primarily a test of whether the application will start.
 * Should be the only test that references Injection.
 */
class ApplicationTest {

    @Test
    fun testHealthcheck() = testSuspend {
        testApp.client.get("/health").apply {
            assertEquals(HttpStatusCode.OK, status)
            assertEquals("OK", bodyAsText())
        }
    }

    companion object {
        private lateinit var testApp: TestApplication

        @BeforeClass
        @JvmStatic
        fun setup() {
            Injection.instance = Injection(
                LDAPConfig("testInvalidUrl", "", "", "", "", "", ""),
                DatabaseConfig("testInvalidUrl", "", ""),
                ClientConfig.fromEnv(),
                DeltaConfig.fromEnv(),
            )
            testApp = TestApplication {
                application {
                    module()
                }
            }
        }
    }
}
