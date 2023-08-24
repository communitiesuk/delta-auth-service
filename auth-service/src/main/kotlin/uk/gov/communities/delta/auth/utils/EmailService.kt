package uk.gov.communities.delta.auth.utils

import org.slf4j.LoggerFactory
import org.thymeleaf.TemplateEngine
import org.thymeleaf.context.Context
import uk.gov.communities.delta.auth.plugins.makeTemplateResolver
import java.util.*
import javax.mail.*
import javax.mail.internet.*

class EmailService() {
    private val logger = LoggerFactory.getLogger(javaClass)

    // TODO - what stuff needs encoding here before sending or is that done earlier?

    fun sendTemplateEmail(
        template: String,
        toEmail: String,
        fromEmail: String,
        fromName: String,
        replyToEmail: String,
        replyToName: String,
        subject: String,
        mappedValues: Map<String, String>,
    ) {
        val templateEngine = TemplateEngine()
        templateEngine.setTemplateResolver(makeTemplateResolver(false))
        val context = Context(Locale.getDefault(), mappedValues)
        val content = templateEngine.process(template, context)
        try {
            println("Emails not set up yet but will send an email to $toEmail with subject $subject and content $content from $fromEmail ($fromName) with replies going to $replyToEmail ($replyToName)")
//            TODO - set this up to send emails
//            val msg: MimeMessage = mailSender.createMimeMessage()
//            msg.setFrom(InternetAddress(fromEmail, fromName, "UTF-8"))
//            msg.replyTo = arrayOf<Address>(
//                InternetAddress(replyToEmail, replyToName, "UTF-8")
//            )
//            msg.setRecipients(Message.RecipientType.TO, toEmail)
//            msg.subject = subject
//            msg.setText(content)
//            msg.setHeader("Content-Type", "text/html")
//            mailSender.send(msg)
        } catch (e: Exception) { // TODO - split into different exceptions for clearer error messages
            logger.error("Failed to sendTemplateEmail, will ignore", e)
        }
    }
}