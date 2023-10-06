package uk.gov.communities.delta.auth.services

import org.slf4j.LoggerFactory
import uk.gov.communities.delta.auth.config.AuthServiceConfig
import uk.gov.communities.delta.auth.config.DeltaConfig
import uk.gov.communities.delta.auth.config.EmailConfig
import uk.gov.communities.delta.auth.config.LDAPConfig
import uk.gov.communities.delta.auth.controllers.external.getSetPasswordURL

class RegistrationService(
    private val deltaConfig: DeltaConfig,
    private val emailConfig: EmailConfig,
    private val ldapConfig: LDAPConfig,
    private val authServiceConfig: AuthServiceConfig,
    private val setPasswordTokenService: SetPasswordTokenService,
    private val emailService: EmailService,
    private val userService: UserService,
    private val userLookupService: UserLookupService,
    private val groupService: GroupService,
) {
    sealed class RegistrationResult
    class UserCreated(val registration: Registration, val token: String, val userCN: String) : RegistrationResult()
    object SSOUserCreated : RegistrationResult()
    class UserAlreadyExists(val registration: Registration) : RegistrationResult()
    class RegistrationFailure(val exception: Exception) : RegistrationResult()

    // Previously users could be datamart users but not delta users, at migration we only transferred over users who
    // were delta users so there should never be users who exist but aren't delta users - therefore can remove all logic
    // for attaching users and checking if they are indeed delta users (if they somehow existed they'd get a "contact
    // the service desk" error at login which is what we want)

    private val logger = LoggerFactory.getLogger(javaClass)

    suspend fun register(
        registration: Registration,
        organisations: List<Organisation>,
        ssoUser: Boolean = false
    ): RegistrationResult {
        val adUser = UserService.ADUser(registration, ssoUser, ldapConfig)
        if (userLookupService.userExists(adUser.cn)) {
            logger.atWarn().addKeyValue("UserDN", adUser.dn).log("User tried to register but user already exists")
            return UserAlreadyExists(registration)
        }
        try {
            userService.createUser(adUser)
            addUserToDefaultGroups(adUser)
            addUserToOrganisations(adUser, organisations)
        } catch (e: Exception) {
            logger.atError().addKeyValue("UserDN", adUser.dn).log("Error creating user", e)
            return RegistrationFailure(e)
        }

        logger.atInfo().addKeyValue("UserDN", adUser.dn).log("User successfully created")
        return if (ssoUser)
            SSOUserCreated
        else
            UserCreated(registration, setPasswordTokenService.createToken(adUser.cn), adUser.cn)
    }

    private suspend fun addUserToDefaultGroups(adUser: UserService.ADUser) {
        try {
            groupService.addUserToGroup(adUser, deltaConfig.datamartDeltaReportUsers)
            groupService.addUserToGroup(adUser, deltaConfig.datamartDeltaUser)
            logger.atInfo().addKeyValue("UserDN", adUser.dn).log("User added to default groups")
        } catch (e: Exception) {
            logger.atError().addKeyValue("UserDN", adUser.dn).log("Error adding user to default groups", e)
            throw e
        }
    }

    private fun organisationUserGroup(orgCode: String): String {
        return String.format("%s-%s", deltaConfig.datamartDeltaUser, orgCode)
    }

    private suspend fun addUserToOrganisations(adUser: UserService.ADUser, organisations: List<Organisation>) {
        logger.atInfo().addKeyValue("UserDN", adUser.dn).log("User added to domain organisations")
        try {
            organisations.forEach {
                if (!it.retired) {
                    groupService.addUserToGroup(
                        adUser,
                        organisationUserGroup(it.code)
                    )
                    logger.atInfo().addKeyValue("UserDN", adUser.dn)
                        .log("Added user to domain organisation with code {}", it.code)
                }
            }
        } catch (e: Exception) {
            logger.atError().addKeyValue("UserDN", adUser.dn).log("Error adding user to domain organisations", e)
            throw e
        }
    }

    private fun getRegistrationEmailContacts(registration: Registration): EmailContacts {
        return EmailContacts(
            registration.emailAddress,
            registration.firstName + " " + registration.lastName,
            emailConfig.fromEmailAddress,
            emailConfig.fromEmailName,
            emailConfig.replyToEmailAddress,
            emailConfig.replyToEmailName,
        )
    }

    fun sendRegistrationEmail(registrationResult: RegistrationResult) {
        try {
            when (registrationResult) {
                is UserCreated -> {
                    emailService.sendTemplateEmail(
                        "new-user",
                        getRegistrationEmailContacts(registrationResult.registration),
                        "DLUHC DELTA - New User Account",
                        mapOf(
                            "deltaUrl" to deltaConfig.deltaWebsiteUrl,
                            "userFirstName" to registrationResult.registration.firstName,
                            "setPasswordUrl" to getSetPasswordURL(
                                registrationResult.token,
                                registrationResult.userCN,
                                authServiceConfig.serviceUrl
                            )
                        )
                    )
                }

                is SSOUserCreated -> {
                    // No email sent
                }

                is UserAlreadyExists -> {
                    emailService.sendTemplateEmail(
                        "already-a-user",
                        getRegistrationEmailContacts(registrationResult.registration),
                        "DLUHC DELTA - Account",
                        mapOf(
                            "deltaUrl" to deltaConfig.deltaWebsiteUrl,
                            "userFirstName" to registrationResult.registration.firstName,
                        )
                    )
                }

                is RegistrationFailure -> {
                    // No email needs to be sent if the registration fails
                }
            }
        } catch (e: Exception) {
            logger.atError().log("Problem sending email", e)
            throw EmailException(e)
        }

    }
}

class EmailException(val e: Exception) : Exception("Issue sending email")

class Registration(
    val firstName: String,
    val lastName: String,
    val emailAddress: String
)

fun getResultTypeString(registrationResult: RegistrationService.RegistrationResult): String {
    return when (registrationResult) {
        is RegistrationService.UserCreated -> {
            "UserCreated"
        }

        is RegistrationService.SSOUserCreated -> {
            "SSOUserCreated"
        }

        is RegistrationService.UserAlreadyExists -> {
            "UserAlreadyExists"
        }

        is RegistrationService.RegistrationFailure -> {
            "RegistrationFailure"
        }
    }
}