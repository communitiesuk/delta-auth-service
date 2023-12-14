package uk.gov.communities.delta.service

import io.ktor.test.dispatcher.*
import io.mockk.*
import jakarta.mail.Authenticator
import jakarta.mail.PasswordAuthentication
import org.junit.Before
import org.junit.Test
import uk.gov.communities.delta.auth.config.AuthServiceConfig
import uk.gov.communities.delta.auth.config.DeltaConfig
import uk.gov.communities.delta.auth.config.EmailConfig
import uk.gov.communities.delta.auth.repositories.EmailRepository
import uk.gov.communities.delta.auth.services.EmailContacts
import uk.gov.communities.delta.auth.services.EmailService
import uk.gov.communities.delta.auth.services.UserAuditService
import uk.gov.communities.delta.helper.testLdapUser
import java.util.*

class EmailServiceTest {

    private val authenticator: Authenticator = object : Authenticator() {
        override fun getPasswordAuthentication(): PasswordAuthentication {
            return PasswordAuthentication("", "")
        }
    }
    private val userAuditService = mockk<UserAuditService>()
    private val emailRepository = mockk<EmailRepository>()
    private val emailConfig = EmailConfig(
        Properties(),
        authenticator,
        "from@test.com",
        "FromName",
        "replyTo@test.com",
        "ReplyToName"
    )
    private val emailService = EmailService(
        emailConfig,
        DeltaConfig("http://delta", 10, ""),
        AuthServiceConfig("http://authservice", null),
        userAuditService,
        emailRepository
    )

    @Test
    fun testSendAlreadyAUserEmail() = testSuspend {
        emailService.sendAlreadyAUserEmail(
            "userFirstName",
            "userCN",
            EmailContacts("test@email.com", "Test Contact", emailConfig)
        ).apply {
            verify(exactly = 1) {
                emailRepository.sendEmail("already-a-user", any(), any(), any())
            }
        }

    }

    @Test
    fun testSendSetPasswordEmail() = testSuspend {
        emailService.sendSetPasswordEmail(testLdapUser(email = "test@user.com"), "token", mockk()).apply {
            verify(exactly = 1) {
                emailRepository.sendEmail("new-user", any(), any(), any())
            }
            coVerify(exactly = 1) { userAuditService.setPasswordEmailAudit(testLdapUser().cn, any()) }
        }
    }

    @Test
    fun testSendNoUserEmail() = testSuspend {
        emailService.sendNoUserEmail("test@email.com").apply {
            verify(exactly = 1) {
                emailRepository.sendEmail("no-user-account", any(), any(), any())
            }
        }
    }

    @Test
    fun testSendNotYetEnabledEmail() = testSuspend {
        emailService.sendNotYetEnabledEmail(testLdapUser(email = "test@user.com"), "token", mockk()).apply {
            verify(exactly = 1) {
                emailRepository.sendEmail("not-yet-enabled-user", any(), any(), any())
            }
            coVerify(exactly = 1) { userAuditService.setPasswordEmailAudit(testLdapUser().cn, any()) }
        }
    }

    @Test
    fun testPasswordNeverSetEmail() = testSuspend {
        emailService.sendPasswordNeverSetEmail(testLdapUser(email = "test@user.com"), "token", mockk()).apply {
            verify(exactly = 1) {
                emailRepository.sendEmail("password-never-set", any(), any(), any())
            }
            coVerify(exactly = 1) { userAuditService.setPasswordEmailAudit(testLdapUser().cn, any()) }
        }

    }

    @Test
    fun testSendResetPasswordEmail() = testSuspend {
        emailService.sendResetPasswordEmail(testLdapUser(email = "test@user.com"), "token", mockk()).apply {
            verify(exactly = 1) {
                emailRepository.sendEmail("reset-password", any(), any(), any())
            }
            coVerify(exactly = 1) { userAuditService.resetPasswordEmailAudit(testLdapUser().cn, any()) }
        }

    }

    @Before
    fun resetMocks() {
        clearAllMocks()
        every { emailRepository.sendEmail(any(), any(), any(), any()) } just runs
        coEvery { userAuditService.setPasswordEmailAudit(any(), any()) } just runs
        coEvery { userAuditService.resetPasswordEmailAudit(any(), any()) } just runs
    }
}