package uk.gov.communities.delta.auth.services

import jakarta.mail.Address
import jakarta.mail.Message
import jakarta.mail.Session
import jakarta.mail.Transport
import jakarta.mail.internet.InternetAddress
import jakarta.mail.internet.MimeMessage
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.jetbrains.annotations.Blocking
import org.slf4j.LoggerFactory
import org.thymeleaf.TemplateEngine
import org.thymeleaf.context.Context
import uk.gov.communities.delta.auth.config.EmailConfig
import uk.gov.communities.delta.auth.plugins.makeTemplateResolver
import uk.gov.communities.delta.auth.plugins.timed
import java.util.*


class EmailService(emailConfig: EmailConfig) {
    private val logger = LoggerFactory.getLogger(javaClass)
    private var session: Session = Session.getInstance(emailConfig.emailProps, emailConfig.emailAuthenticator)
    private var templateEngine: TemplateEngine = TemplateEngine()

    init {
        val templateResolver = templateEngine.makeTemplateResolver()
        templateResolver.prefix += "emails/"
        templateEngine.setTemplateResolver(templateResolver)
    }

    suspend fun sendTemplateEmail(
        template: String,
        emailContacts: EmailContacts,
        subject: String,
        mappedValues: Map<String, String>,
    ) {
        withContext(Dispatchers.IO) {
            logger.timed(
                "Send templated email",
                { listOf(Pair("emailTemplate", template)) }
            ) {
                blockingSendEmail(template, emailContacts, subject, mappedValues)
            }
        }
    }

    @Blocking
    private fun blockingSendEmail(
        template: String,
        emailContacts: EmailContacts,
        subject: String,
        mappedValues: Map<String, String>,
    ) {
        val context = Context(Locale.getDefault(), mappedValues)
        val content = templateEngine.process(template, context)
        logger.atInfo()
            .addKeyValue("emailTemplate", template)
            .addKeyValue("emailTo", emailContacts.getTo())
            .addKeyValue("emailSubject", subject)
            .log("Sending email")
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
        } catch (e: Exception) {
            logger.error("Failed to sendTemplateEmail", e)
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
