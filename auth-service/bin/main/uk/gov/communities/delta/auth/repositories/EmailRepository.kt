package uk.gov.communities.delta.auth.repositories

import jakarta.mail.Message
import jakarta.mail.Session
import jakarta.mail.Transport
import jakarta.mail.internet.MimeMessage
import org.jetbrains.annotations.Blocking
import org.slf4j.LoggerFactory
import org.thymeleaf.TemplateEngine
import org.thymeleaf.context.Context
import uk.gov.communities.delta.auth.config.EmailConfig
import uk.gov.communities.delta.auth.plugins.makeTemplateResolver
import uk.gov.communities.delta.auth.services.EmailContacts
import java.util.*

class EmailRepository(emailConfig: EmailConfig) {

    private val logger = LoggerFactory.getLogger(javaClass)
    private var session: Session = Session.getInstance(emailConfig.emailProps, emailConfig.emailAuthenticator)
    private var templateEngine: TemplateEngine = TemplateEngine()

    init {
        val templateResolver = templateEngine.makeTemplateResolver()
        templateResolver.prefix += "emails/"
        templateEngine.setTemplateResolver(templateResolver)
    }

    @Blocking
    fun sendEmail(
        template: String,
        emailContacts: EmailContacts,
        subject: String,
        mappedValues: Map<String, String>,
    ) {
        val context = Context(Locale.getDefault(), mappedValues)
        val content = templateEngine.process(template, context)
        logger.atInfo()
            .addKeyValue("emailTemplate", template)
            .addKeyValue("emailTo", emailContacts.getTo().joinToString(";"))
            .addKeyValue("emailSubject", subject)
            .log("Sending email")
        try {
            val msg: Message = MimeMessage(session)
            msg.setFrom(emailContacts.getFrom())
            msg.replyTo = arrayOf(
                emailContacts.getReplyTo()
            )
            msg.setRecipients(
                Message.RecipientType.TO, emailContacts.getTo()
            )
            msg.subject = subject
            msg.setText(content)
            msg.setHeader("Content-Type", "text/html")
            Transport.send(msg)
        } catch (e: Exception) {
            logger.error("Failed to sendTemplateEmail", e)
            throw e
        }
    }
}
