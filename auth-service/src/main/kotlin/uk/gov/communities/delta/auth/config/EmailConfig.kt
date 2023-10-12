package uk.gov.communities.delta.auth.config

import jakarta.mail.Authenticator
import jakarta.mail.PasswordAuthentication
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import org.slf4j.spi.LoggingEventBuilder
import java.util.*
import kotlin.time.Duration.Companion.seconds

class EmailConfig(
    val emailProps: Properties,
    val emailAuthenticator: Authenticator,
    val fromEmailAddress: String,
    val fromEmailName: String,
    val replyToEmailAddress: String,
    val replyToEmailName: String,
) {
    companion object {
        fun fromEnv(): EmailConfig {
            val smtpUsername: String?
            val smtpPassword: String?
            val props = Properties()
            val smtpUserJSON = Env.getEnv("MAIL_SMTP_USER")
            val useAuth = smtpUserJSON != null
            if (useAuth){
                val smtpMailUser = Json.decodeFromString<MailSMTPUserBody>(smtpUserJSON!!)
                smtpUsername = smtpMailUser.username
                smtpPassword = smtpMailUser.password
            } else {
                smtpUsername = null
                smtpPassword = null
            }
            val authenticator: Authenticator = object : Authenticator() {
                override fun getPasswordAuthentication(): PasswordAuthentication {
                    return PasswordAuthentication(smtpUsername ?: "", smtpPassword ?: "")
                }

                override fun toString(): String {
                    return smtpUsername ?: "No value for MAIL_SMTP_USERNAME"
                }
            }
            props["mail.smtp.auth"] = useAuth
            props["mail.smtp.starttls.enable"] = useAuth
            props["mail.smtp.host"] = Env.getRequiredOrDevFallback("MAIL_SMTP_HOST", "localhost")
            props["mail.smtp.port"] = Env.getRequiredOrDevFallback("MAIL_SMTP_PORT", "25")
            props["mail.smtp.timeout"] = 10.seconds.inWholeMilliseconds
            @Suppress("SpellCheckingInspection")
            props["mail.smtp.connectiontimeout"] = 10.seconds.inWholeMilliseconds
            return EmailConfig(
                emailProps = props,
                emailAuthenticator = authenticator,
                fromEmailAddress = Env.getRequiredOrDevFallback("FROM_EMAIL_ADDRESS", "testFromEmail@softwire.com"),
                fromEmailName = Env.getRequiredOrDevFallback("FROM_EMAIL_NAME", "Test From Email"),
                replyToEmailAddress = Env.getRequiredOrDevFallback(
                    "REPLY_TO_EMAIL_ADDRESS",
                    "testReplyTo@softwire.com"
                ),
                replyToEmailName = Env.getRequiredOrDevFallback("REPLY_TO_EMAIL_NAME", "Test Reply To Email"),
            )
        }
    }

    fun log(logger: LoggingEventBuilder) {
        logger.addKeyValue("MAIL_SMTP_HOST", emailProps["mail.smtp.host"])
            .addKeyValue("MAIL_SMTP_PORT", emailProps["mail.smtp.port"])
            .addKeyValue("MAIL_SMTP_USERNAME", emailAuthenticator.toString())
            .log("Email config")
    }
}

@Serializable
data class MailSMTPUserBody(
    @SerialName("username") val username: String,
    @SerialName("password") val password: String,
)
