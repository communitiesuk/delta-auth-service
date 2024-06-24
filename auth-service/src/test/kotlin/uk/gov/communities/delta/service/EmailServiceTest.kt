package uk.gov.communities.delta.service

import io.ktor.server.application.*
import io.ktor.server.auth.*
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
import uk.gov.communities.delta.auth.services.OAuthSession
import uk.gov.communities.delta.auth.services.UserAuditService
import uk.gov.communities.delta.helper.testLdapUser
import uk.gov.communities.delta.helper.testOpenTelemetry
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
        "ReplyToName",
        false,
        emptyList(),
    )
    private val emailService = EmailService(
        emailConfig,
        DeltaConfig("http://delta", 10, "", "localhost"),
        AuthServiceConfig("http://authservice", null),
        userAuditService,
        emailRepository,
        testOpenTelemetry.getTracer("test-email-tracer"),
    )
    private val user = testLdapUser(email = "test@user.com")
    private val adminGUID = UUID.fromString("ffeeddcc-bbaa-9988-7766-554433221100")

    @Test
    fun testSendAlreadyAUserEmail() = testSuspend {
        emailService.sendAlreadyAUserEmail(
            user.firstName,
            user.getGUID(),
            EmailContacts(user.email!!, user.fullName, emailConfig)
        ).apply {
            verify(exactly = 1) {
                emailRepository.sendEmail("already-a-user", any(), any(), any())
            }
        }

    }

    @Test
    fun testSendSelfSetPasswordEmail() = testSuspend {
        emailService.sendSetPasswordEmail(user, "token", null, mockk()).apply {
            verify(exactly = 1) { emailRepository.sendEmail("new-user", any(), any(), any()) }
            coVerify(exactly = 1) { userAuditService.setPasswordEmailAudit(user.getGUID(), any()) }
        }
    }

    @Test
    fun testSendAdminSetPasswordEmail() = testSuspend {
        val call = mockk<ApplicationCall>()
        val adminSession = mockk<OAuthSession>()
        coEvery { adminSession.userGUID } returns adminGUID
        coEvery { call.principal<OAuthSession>() } returns adminSession
        emailService.sendSetPasswordEmail(user, "token", adminSession, call).apply {
            verify(exactly = 1) { emailRepository.sendEmail("new-user", any(), any(), any()) }
            coVerify(exactly = 1) { userAuditService.adminSetPasswordEmailAudit(user.getGUID(), adminGUID, any()) }
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
        emailService.sendNotYetEnabledEmail(user, "token", mockk()).apply {
            verify(exactly = 1) {
                emailRepository.sendEmail("not-yet-enabled-user", any(), any(), any())
            }
            coVerify(exactly = 1) { userAuditService.setPasswordEmailAudit(user.getGUID(), any()) }
        }
    }

    @Test
    fun testPasswordNeverSetEmail() = testSuspend {
        emailService.sendPasswordNeverSetEmail(user, "token", mockk()).apply {
            verify(exactly = 1) {
                emailRepository.sendEmail("password-never-set", any(), any(), any())
            }
            coVerify(exactly = 1) { userAuditService.setPasswordEmailAudit(user.getGUID(), any()) }
        }

    }

    @Test
    fun testSendSelfResetPasswordEmail() = testSuspend {
        emailService.sendResetPasswordEmail(user, "token", null, mockk()).apply {
            verify(exactly = 1) {
                emailRepository.sendEmail("reset-password", any(), any(), any())
            }
            coVerify(exactly = 1) { userAuditService.resetPasswordEmailAudit(user.getGUID(), any()) }
        }
    }

    @Test
    fun testSendAdminResetPasswordEmail() = testSuspend {
        val call = mockk<ApplicationCall>()
        val adminSession = mockk<OAuthSession>()
        coEvery { call.principal<OAuthSession>() } returns adminSession
        coEvery { adminSession.userGUID } returns adminGUID
        emailService.sendResetPasswordEmail(user, "token", adminSession, call).apply {
            verify(exactly = 1) { emailRepository.sendEmail("reset-password", any(), any(), any()) }
            coVerify(exactly = 1) { userAuditService.adminResetPasswordEmailAudit(user.getGUID(), adminGUID, any()) }
        }
    }

    @Before
    fun resetMocks() {
        clearAllMocks()
        every { emailRepository.sendEmail(any(), any(), any(), any()) } just runs
        coEvery { userAuditService.setPasswordEmailAudit(any(), any()) } just runs
        coEvery { userAuditService.resetPasswordEmailAudit(any(), any()) } just runs
        coEvery { userAuditService.adminSetPasswordEmailAudit(any(), any(), any()) } just runs
        coEvery { userAuditService.adminResetPasswordEmailAudit(any(), any(), any()) } just runs
    }
}
