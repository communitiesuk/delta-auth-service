package uk.gov.communities.delta.auth.plugins

import io.ktor.http.*
import io.ktor.http.content.*
import io.ktor.server.application.*
import io.ktor.server.plugins.cachingheaders.*
import io.ktor.server.response.*

val CSP = createRouteScopedPlugin("CSP") {

    onCallRespond { call ->
        call.addCSPHeader()
    }
}


fun ApplicationCall.addCSPHeader() {
    response.header(
        "Content-Security-Policy",
        "default-src 'self'"
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