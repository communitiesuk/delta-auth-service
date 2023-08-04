package uk.gov.communities.delta.auth.security

import io.ktor.server.application.*
import io.ktor.server.plugins.*
import io.ktor.server.plugins.forwardedheaders.*
import io.ktor.server.plugins.ratelimit.*
import org.slf4j.LoggerFactory
import uk.gov.communities.delta.auth.config.Env
import kotlin.time.Duration.Companion.minutes

fun Application.configureRateLimiting() {
    val logger = LoggerFactory.getLogger("Application.RateLimiting")
    val rateLimit = Env.getRequiredOrDevFallback("AUTH_RATE_LIMIT", "10").toInt()

    install(XForwardedHeaders) {
        this.skipLastProxies(1)
    }
    install(RateLimit) {
        // Currently only the login page is rate limited so a status 429 (Too many requests) sends the login page (with an error message)
        register(RateLimitName("protectLogin")) {
            rateLimiter(limit = rateLimit, refillPeriod = 5.minutes)
            requestKey { applicationCall ->
                val remoteHost = applicationCall.request.origin.remoteHost
                logger.info("Request to login page from $remoteHost")
                remoteHost
            }
            modifyResponse { applicationCall, state ->
                if (state is RateLimiter.State.Exhausted){
                    val remoteHost = applicationCall.request.origin.remoteHost
                    logger.warn("Rate Limit reached for IP Address $remoteHost")
                }
            }
        }
    }
}
