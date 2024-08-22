package uk.gov.communities.delta.auth.utils

import java.time.Instant

// Wrapper around Instant.now() to make testing easier
interface TimeSource {
    fun now(): Instant

    class SystemTime : TimeSource {
        override fun now(): Instant = Instant.now()
    }

    companion object {
        val System = SystemTime()
    }
}
