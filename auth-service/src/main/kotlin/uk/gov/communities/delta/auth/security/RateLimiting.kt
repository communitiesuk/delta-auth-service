package uk.gov.communities.delta.auth.security

import io.ktor.server.application.*
import io.ktor.server.plugins.*
import io.ktor.server.plugins.forwardedheaders.*
import io.ktor.server.plugins.ratelimit.*
import io.micrometer.core.instrument.Counter
import org.slf4j.LoggerFactory
import kotlin.time.Duration.Companion.minutes

const val loginRateLimitName = "protectLogin"
const val registrationRateLimitName = "protectRegistration"
const val setPasswordRateLimitName = "protectSetPassword"

fun Application.configureRateLimiting(
    rateLimit: Int,
    loginRateLimitCounter: Counter,
    registrationRateLimitCounter: Counter,
    setPasswordRateLimitCounter: Counter,
) {
    val logger = LoggerFactory.getLogger("Application.RateLimiting")

    fun RateLimitConfig.setUpRateLimit(rateLimitName: String, pageName: String, counter: Counter) {
        register(RateLimitName(rateLimitName)) {
            rateLimiter(limit = rateLimit, refillPeriod = 5.minutes)
            requestKey { applicationCall ->
                val ipAddress = applicationCall.request.origin.remoteAddress
                logger.info("Request to $pageName page from $ipAddress")
                ipAddress
            }
            modifyResponse { applicationCall, state ->
                if (state is RateLimiter.State.Exhausted) {
                    val ipAddress = applicationCall.request.origin.remoteAddress
                    counter.increment(1.0)
                    logger.warn("$pageName page rate limit reached for IP Address $ipAddress")
                }
            }
        }
    }

    install(XForwardedHeaders) {
        this.skipLastProxies(1)
    }
    install(RateLimit) {
        setUpRateLimit(loginRateLimitName, "Login", loginRateLimitCounter)
        setUpRateLimit(registrationRateLimitName, "Registration form", registrationRateLimitCounter)
        setUpRateLimit(setPasswordRateLimitName, "Set Password form", setPasswordRateLimitCounter)
    }
}
