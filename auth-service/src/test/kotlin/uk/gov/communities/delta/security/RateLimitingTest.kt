package uk.gov.communities.delta.security

import io.ktor.client.*
import io.ktor.client.request.*
import io.ktor.client.statement.*
import io.ktor.http.*
import io.ktor.server.application.*
import io.ktor.server.plugins.ratelimit.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import io.ktor.server.testing.*
import io.ktor.test.dispatcher.*
import org.junit.AfterClass
import org.junit.BeforeClass
import org.junit.Test
import uk.gov.communities.delta.auth.config.AzureADSSOConfig
import uk.gov.communities.delta.auth.plugins.configureStatusPages
import uk.gov.communities.delta.auth.plugins.configureTemplating
import uk.gov.communities.delta.auth.security.configureRateLimiting
import uk.gov.communities.delta.auth.security.loginRateLimitName
import uk.gov.communities.delta.helper.testServiceClient
import kotlin.test.assertContains
import kotlin.test.assertEquals
import kotlin.test.assertFalse

class RateLimitingTest {

    // Assert that a successful request gets the expected outcome
    private suspend fun assertSuccessfulGetRequest(forwardFor: String) {
        testClient.get("/delta/login?response_type=code&client_id=delta-website&state=1234") {
            headers {
                append("X-Forwarded-For", forwardFor)
            }
        }.apply {
            assertEquals(HttpStatusCode.OK, status)
            assertEquals("Get request allowed through", bodyAsText())
            assertFalse(bodyAsText().contains("Too many requests from your location, please try again in a few minutes."))
        }
    }

    // Assert that the correct page/error message is being passed to blocked requests
    private suspend fun assertBlockedGetRequest(forwardFor: String) {
        testClient.get("/delta/login?response_type=code&client_id=delta-website&state=1234") {
            headers {
                append("X-Forwarded-For", forwardFor)
            }
        }.apply {
            assertContains(bodyAsText(), "<title>DELTA | Sign in</title>")
            assertContains(bodyAsText(), "<a href=\"\">Too many requests from your location, please try again in a few minutes.</a>")
        }
    }

    @Test
    fun testLoginPageRateLimit() = testSuspend {
        val forwardedFor = "5.6.7.8, 1.2.3.4, 5.6.7.8"
        for (i in 1..rateLimitValue) {
            assertSuccessfulGetRequest(forwardedFor)
        }
        assertBlockedGetRequest(forwardedFor)
    }

    @Test
    fun testLoginPageRateLimitPerUser() = testSuspend {
        // Test that varying the penultimate address causes requests not to be blocked by other address' usage
        val forwardFor1 = "5.6.7.8, 2.3.4.5, 5.6.7.8"
        val forwardFor2 = "5.6.7.8, 5.4.3.2, 5.6.7.8"
        for (i in 1..rateLimitValue) {
            assertSuccessfulGetRequest(forwardFor1)
        }
        assertBlockedGetRequest(forwardFor1)
        assertSuccessfulGetRequest(forwardFor2)
    }

    companion object {
        private lateinit var testApp: TestApplication
        private lateinit var testClient: HttpClient
        val client = testServiceClient()
        private const val rateLimitValue = 2

        @BeforeClass
        @JvmStatic
        fun setup() {
            testApp = TestApplication {
                application {
                    configureTemplating(false)
                    configureRateLimiting(rateLimitValue)
                    configureStatusPages("test.url", AzureADSSOConfig(emptyList()))
                    routing {
                        rateLimit(RateLimitName(loginRateLimitName)) {
                            route("/delta/login") {
                                this.get{
                                    call.respondText("Get request allowed through")
                                }
                                this.post {
                                    call.respondText("Post request allowed through")
                                }
                            }
                        }
                    }
                }
            }
            testClient = testApp.createClient { followRedirects = false }
        }

        @AfterClass
        @JvmStatic
        fun tearDown() {
            testApp.stop()
        }
    }
}
