package uk.gov.communities.delta.auth.plugins

import io.ktor.server.application.*
import io.ktor.server.thymeleaf.*
import org.thymeleaf.templateresolver.ClassLoaderTemplateResolver
import org.thymeleaf.templateresolver.FileTemplateResolver

fun Application.configureTemplating() {
    install(Thymeleaf) {
        setTemplateResolver((if (developmentMode) {
            log.info("Development mode, using templates from src/ folder")
            FileTemplateResolver().apply {
                cacheManager = null
                prefix = "auth-service/src/main/resources/templates/thymeleaf/"
            }
        } else {
            ClassLoaderTemplateResolver().apply {
                prefix = "templates/thymeleaf/"
            }
        }).apply {
            suffix = ".html"
            characterEncoding = "utf-8"
        })
    }
}
