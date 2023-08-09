package uk.gov.communities.delta.auth.plugins

import io.ktor.server.application.*
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
