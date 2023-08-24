package uk.gov.communities.delta.auth.plugins

import io.ktor.server.application.*
import io.ktor.server.thymeleaf.*
import org.slf4j.LoggerFactory
import org.thymeleaf.templateresolver.AbstractConfigurableTemplateResolver
import org.thymeleaf.templateresolver.ClassLoaderTemplateResolver
import org.thymeleaf.templateresolver.FileTemplateResolver

fun Application.configureTemplating(devMode: Boolean) {
    install(Thymeleaf) {
        setTemplateResolver(makeTemplateResolver(devMode))
    }
}

fun makeTemplateResolver(devMode: Boolean): AbstractConfigurableTemplateResolver {
    val logger = LoggerFactory.getLogger("Application.Templating")

    return (if (devMode) {
        logger.info("Development mode, using templates from src/ folder")
        FileTemplateResolver().apply {
//            cacheManager = null // TODO - add this back in?
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
