package uk.gov.communities.delta.auth.plugins

import io.ktor.server.application.*
import io.ktor.server.thymeleaf.*
import org.slf4j.LoggerFactory
import org.thymeleaf.TemplateEngine
import org.thymeleaf.templateresolver.AbstractConfigurableTemplateResolver
import org.thymeleaf.templateresolver.ClassLoaderTemplateResolver
import org.thymeleaf.templateresolver.FileTemplateResolver

fun Application.configureTemplating(devMode: Boolean) {
    install(Thymeleaf) {
        this.setTemplateResolver(makeTemplateResolver(devMode))
    }
}

fun TemplateEngine.makeTemplateResolver(devMode: Boolean = false): AbstractConfigurableTemplateResolver {
    val logger = LoggerFactory.getLogger("Application.Templating")

    return (if (devMode) {
        logger.info("Development mode, using templates from src/ folder")
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
    }
}
