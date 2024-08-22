package uk.gov.communities.delta

import io.ktor.client.request.*
import io.ktor.client.statement.*
import io.ktor.http.*
import io.ktor.server.testing.*
import io.ktor.test.dispatcher.*
import org.junit.BeforeClass
import org.slf4j.helpers.NOPLogger
import uk.gov.communities.delta.auth.Injection
import uk.gov.communities.delta.auth.appModule
import uk.gov.communities.delta.auth.config.*
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
            val deltaConfig = DeltaConfig.fromEnv()
            Injection.instance = Injection(
                LDAPConfig("testInvalidUrl", "", "", "", "", "", "", "", ""),
                DatabaseConfig("testInvalidUrl", "", ""),
                ClientConfig.fromEnv(deltaConfig),
                deltaConfig,
                EmailConfig.fromEnv(),
                AzureADSSOConfig(emptyList()),
                AuthServiceConfig("testInvalidServiceUrl", null),
                TracingConfig(null),
            )
            Injection.instance.logConfig(NOPLogger.NOP_LOGGER)
            testApp = TestApplication {
                application {
                    appModule()
                }
            }
        }
    }
}
