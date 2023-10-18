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
import io.micrometer.core.instrument.Counter
import io.mockk.clearAllMocks
import io.mockk.every
import io.mockk.mockk
import io.mockk.verify
import org.junit.AfterClass
import org.junit.Before
import org.junit.BeforeClass
import org.junit.Test
import uk.gov.communities.delta.auth.config.AzureADSSOConfig
import uk.gov.communities.delta.auth.config.DeltaConfig
import uk.gov.communities.delta.auth.plugins.configureStatusPages
import uk.gov.communities.delta.auth.plugins.configureTemplating
import uk.gov.communities.delta.auth.security.*
import uk.gov.communities.delta.helper.testServiceClient
import kotlin.test.assertContains
import kotlin.test.assertEquals
import kotlin.test.assertFalse

class RateLimitingTest {

    // Assert that a successful request gets the expected outcome
    private suspend fun assertSuccessfulGetRequest(forwardFor: String, url: String) {
        testClient.get(url) {
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
    private suspend fun assertBlockedGetRequest(forwardFor: String, url: String, assertionText: String) {
        testClient.get(url) {
            headers {
                append("X-Forwarded-For", forwardFor)
            }
        }.apply {
            assertContains(bodyAsText(), assertionText)
            assertContains(
                bodyAsText(),
                "Too many requests from your location, please try again in a few minutes."
            )
        }
    }

    @Test
    fun testLoginPageRateLimit() = testSuspend {
        val forwardedFor = "5.6.7.8, 1.2.3.4, 5.6.7.8"
        for (i in 1..rateLimitValue) {
            assertSuccessfulGetRequest(
                forwardedFor,
                "/delta/login?response_type=code&client_id=delta-website&state=1234"
            )
        }
        assertBlockedGetRequest(
            forwardedFor,
            "/delta/login?response_type=code&client_id=delta-website&state=1234",
            "<title>DELTA | Sign in</title>"
        )
        verify(exactly = 1) { rateLimitLoginCounter.increment(1.0) }
    }

    @Test
    fun testLoginPageRateLimitPerUser() = testSuspend {
        // Test that varying the penultimate address causes requests not to be blocked by other address' usage
        val forwardFor1 = "5.6.7.8, 2.3.4.5, 5.6.7.8"
        val forwardFor2 = "5.6.7.8, 5.4.3.2, 5.6.7.8"
        for (i in 1..rateLimitValue) {
            assertSuccessfulGetRequest(
                forwardFor1,
                "/delta/login?response_type=code&client_id=delta-website&state=1234"
            )
        }
        assertBlockedGetRequest(
            forwardFor1,
            "/delta/login?response_type=code&client_id=delta-website&state=1234",
            "<title>DELTA | Sign in</title>"
        )
        assertSuccessfulGetRequest(forwardFor2, "/delta/login?response_type=code&client_id=delta-website&state=1234")
        verify(exactly = 1) { rateLimitLoginCounter.increment(1.0) }
    }

    @Test
    fun testRegistrationPageRateLimit() = testSuspend {
        val forwardedFor = "5.6.7.8, 1.2.3.4, 5.6.7.8"
        for (i in 1..rateLimitValue) {
            assertSuccessfulGetRequest(forwardedFor, "/delta/register")
        }
        assertBlockedGetRequest(forwardedFor, "/delta/register", "<title>DELTA | Register</title>")
        verify(exactly = 1) { rateLimitRegistrationCounter.increment(1.0) }
    }

    @Test
    fun testSetPasswordPageRateLimit() = testSuspend {
        val forwardedFor = "5.6.7.8, 1.2.3.4, 5.6.7.8"
        for (i in 1..rateLimitValue) {
            assertSuccessfulGetRequest(forwardedFor, "/delta/set-password")
        }
        assertBlockedGetRequest(forwardedFor, "/delta/set-password", "<title>Delta | Password</title>")
        verify(exactly = 1) { rateLimitSetPasswordCounter.increment(1.0) }
    }

    @Test
    fun testResetPasswordPageRateLimit() = testSuspend {
        val forwardedFor = "5.6.7.8, 1.2.3.4, 5.6.7.8"
        for (i in 1..rateLimitValue) {
            assertSuccessfulGetRequest(forwardedFor, "/delta/reset-password")
        }
        assertBlockedGetRequest(forwardedFor, "/delta/reset-password", "<title>Delta | Password</title>")
        verify(exactly = 1) { rateLimitResetPasswordCounter.increment(1.0) }
    }

    @Test
    fun testForgotPasswordPageRateLimit() = testSuspend {
        val forwardedFor = "5.6.7.8, 1.2.3.4, 5.6.7.8"
        for (i in 1..rateLimitValue) {
            assertSuccessfulGetRequest(forwardedFor, "/delta/forgot-password")
        }
        assertBlockedGetRequest(forwardedFor, "/delta/forgot-password", "<title>Delta | Forgot Password</title>")
        verify(exactly = 1) { rateLimitForgotPasswordCounter.increment(1.0) }
    }

    @Test
    fun testRateLimitPerUserPerPage() = testSuspend {
        // Test that different pages have independent rate limits
        val forwardFor1 = "5.6.7.8, 3.4.5.6, 5.6.7.8"
        val forwardFor2 = "5.6.7.8, 6.5.4.3, 5.6.7.8"
        for (i in 1..rateLimitValue) {
            assertSuccessfulGetRequest(forwardFor1, "/delta/set-password")
        }
        assertBlockedGetRequest(forwardFor1, "/delta/set-password", "<title>Delta | Password</title>")
        assertSuccessfulGetRequest(forwardFor2, "/delta/set-password")
        assertSuccessfulGetRequest(forwardFor1, "delta/register")
        verify(exactly = 1) { rateLimitSetPasswordCounter.increment(1.0) }
    }

    @Before
    fun resetCounter() {
        clearAllMocks()
        every { rateLimitLoginCounter.increment(1.0) } returns Unit
        every { rateLimitRegistrationCounter.increment(1.0) } returns Unit
        every { rateLimitSetPasswordCounter.increment(1.0) } returns Unit
        every { rateLimitResetPasswordCounter.increment(1.0) } returns Unit
        every { rateLimitForgotPasswordCounter.increment(1.0) } returns Unit
    }

    companion object {
        private lateinit var testApp: TestApplication
        private lateinit var testClient: HttpClient
        val client = testServiceClient()
        private const val rateLimitValue = 2
        val rateLimitLoginCounter = mockk<Counter>()
        val rateLimitRegistrationCounter = mockk<Counter>()
        val rateLimitSetPasswordCounter = mockk<Counter>()
        val rateLimitResetPasswordCounter = mockk<Counter>()
        val rateLimitForgotPasswordCounter = mockk<Counter>()

        @BeforeClass
        @JvmStatic
        fun setup() {
            fun Route.respondSuccess() {
                this.get {
                    call.respondText("Get request allowed through")
                }
                this.post {
                    call.respondText("Post request allowed through")
                }
            }
            testApp = TestApplication {
                application {
                    configureTemplating(false)
                    configureRateLimiting(
                        rateLimitValue,
                        rateLimitLoginCounter,
                        rateLimitRegistrationCounter,
                        rateLimitSetPasswordCounter,
                        rateLimitResetPasswordCounter,
                        rateLimitForgotPasswordCounter,
                    )
                    configureStatusPages(
                        "test.url",
                        AzureADSSOConfig(emptyList()),
                        DeltaConfig("url", rateLimitValue, "")
                    )
                    routing {
                        rateLimit(RateLimitName(loginRateLimitName)) {
                            route("/delta/login") {
                                this.respondSuccess()
                            }
                        }
                        rateLimit(RateLimitName(registrationRateLimitName)) {
                            route("/delta/register") {
                                this.respondSuccess()
                            }
                        }
                        rateLimit(RateLimitName(setPasswordRateLimitName)) {
                            route("/delta/set-password") {
                                this.respondSuccess()
                            }
                        }
                        rateLimit(RateLimitName(resetPasswordRateLimitName)) {
                            route("/delta/reset-password") {
                                this.respondSuccess()
                            }
                        }
                        rateLimit(RateLimitName(forgotPasswordRateLimitName)) {
                            route("/delta/forgot-password") {
                                this.respondSuccess()
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
