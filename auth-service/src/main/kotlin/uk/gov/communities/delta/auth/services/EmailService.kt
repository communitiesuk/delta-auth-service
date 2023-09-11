package uk.gov.communities.delta.auth.services

import jakarta.mail.Address
import jakarta.mail.Message
import jakarta.mail.Session
import jakarta.mail.Transport
import jakarta.mail.internet.InternetAddress
import jakarta.mail.internet.MimeMessage
import org.slf4j.LoggerFactory
import org.thymeleaf.TemplateEngine
import org.thymeleaf.context.Context
import uk.gov.communities.delta.auth.config.EmailConfig
import uk.gov.communities.delta.auth.plugins.makeTemplateResolver
import java.util.*


class EmailService(private val emailConfig: EmailConfig) {
    private val logger = LoggerFactory.getLogger(javaClass)
//    TODO - check everything is encoded correctly?

    fun sendTemplateEmail(
        template: String,
        emailContacts: EmailContacts,
        subject: String,
        mappedValues: Map<String, String>,
    ) {
        val session = Session.getInstance(emailConfig.emailProps, emailConfig.emailAuthenticator)
        val templateEngine = TemplateEngine()
        val templateResolver = templateEngine.makeTemplateResolver()
        templateResolver.prefix = templateResolver.prefix + "emails/"
        templateEngine.setTemplateResolver(templateResolver)
        val context = Context(Locale.getDefault(), mappedValues)
        val content = templateEngine.process(template, context)
        try {
            val msg: Message = MimeMessage(session)
            msg.setFrom(emailContacts.getFrom())
            msg.replyTo = arrayOf(
                emailContacts.getReplyTo()
            )
            msg.setRecipients(
                Message.RecipientType.TO, arrayOf(
                    emailContacts.getTo()
                )
            )
            msg.subject = subject
            msg.setText(content)
            msg.setHeader("Content-Type", "text/html")
            Transport.send(msg)
        } catch (e: Exception) { // TODO - split into different exceptions for clearer error messages
            logger.error("Failed to sendTemplateEmail, will ignore", e)
            throw e
        }
    }
}

class EmailContacts(
    private val toEmail: String,
    private val toName: String,
    private val fromEmail: String,
    private val fromName: String,
    private val replyToEmail: String,
    private val replyToName: String,
) {
    fun getTo(): Address {
        return InternetAddress(toEmail, toName, "UTF-8")
    }

    fun getFrom(): Address {
        return InternetAddress(fromEmail, fromName, "UTF-8")
    }

    fun getReplyTo(): Address {
        return InternetAddress(replyToEmail, replyToName, "UTF-8")
    }
}