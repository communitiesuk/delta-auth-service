package uk.gov.communities.delta.auth.controllers

import io.ktor.server.application.*
import io.ktor.server.response.*
import io.ktor.server.thymeleaf.*
import uk.gov.communities.delta.auth.config.DeltaConfig

class PublicDeltaLoginController {
    suspend fun getLoginPage(call: ApplicationCall) {
        call.respond(
            ThymeleafContent(
                "delta-login", mapOf(
                    "deltaUrl" to DeltaConfig.DELTA_WEBSITE_URL
                )
            )
        )
    }
}
