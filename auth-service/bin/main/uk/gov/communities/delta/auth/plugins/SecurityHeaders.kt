package uk.gov.communities.delta.auth.plugins

import io.ktor.http.*
import io.ktor.http.content.*
import io.ktor.server.application.*
import io.ktor.server.plugins.cachingheaders.*
import io.ktor.server.response.*

val BrowserSecurityHeaders = createRouteScopedPlugin("CSP") {
    onCallRespond { call ->
        call.addSecurityHeaders()
    }
}

fun ApplicationCall.addSecurityHeaders() {
    response.header(
        "Content-Security-Policy",
        "default-src 'self'"
    )
    response.header(
        "Referrer-Policy",
        "same-origin"
    )
}

fun Application.installCachingHeaders() {
    install(CachingHeaders) {
        options { call, _ ->
            if (call.response.headers["Cache-Control"] == null)
                CachingOptions(CacheControl.NoStore(CacheControl.Visibility.Private))
            else null
        }
    }
}
