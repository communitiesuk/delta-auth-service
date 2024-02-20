package uk.gov.communities.delta.auth.services

import io.ktor.server.application.*
import io.ktor.server.auth.*
import org.slf4j.LoggerFactory
import uk.gov.communities.delta.auth.config.AzureADSSOClient
import uk.gov.communities.delta.auth.config.DeltaConfig
import uk.gov.communities.delta.auth.config.EmailConfig
import uk.gov.communities.delta.auth.config.LDAPConfig

class RegistrationService(
    private val deltaConfig: DeltaConfig,
    private val emailConfig: EmailConfig,
    private val ldapConfig: LDAPConfig,
    private val setPasswordTokenService: SetPasswordTokenService,
    private val emailService: EmailService,
    private val userService: UserService,
    private val userLookupService: UserLookupService,
    private val groupService: GroupService,
) {
    sealed class RegistrationResult
    class UserCreated(val user: UserService.ADUser, val token: String) : RegistrationResult()
    class SSOUserCreated(val userCN: String) : RegistrationResult()
    class UserAlreadyExists(val user: UserService.ADUser) : RegistrationResult()
    class RegistrationFailure(val exception: Exception) : RegistrationResult()

    // Previously users could be datamart users but not delta users, at migration we only transferred over users who
    // were delta users so there should never be users who exist but aren't delta users - therefore can remove all logic
    // for attaching users and checking if they are indeed delta users (if they somehow existed they'd get a "contact
    // the service desk" error at login which is what we want)

    private val logger = LoggerFactory.getLogger(javaClass)

    suspend fun register(
        registration: Registration,
        organisations: List<Organisation>,
        call: ApplicationCall,
        ssoClient: AzureADSSOClient? = null,
        azureObjectId: String? = null,
    ): RegistrationResult {
        val adUser = UserService.ADUser(ldapConfig, registration, ssoClient)

        if (userLookupService.userExists(adUser.cn)) {
            logger.atWarn().addKeyValue("UserDN", adUser.dn).log("User tried to register but user already exists")
            return UserAlreadyExists(adUser)
        }
        try {
            userService.createUser(adUser, ssoClient, call.principal<OAuthSession>(), call, azureObjectId)
            addUserToDefaultGroups(adUser, call)
            addUserToOrganisations(adUser, organisations, call)
        } catch (e: Exception) {
            logger.atError().addKeyValue("UserDN", adUser.dn).log("Error creating user", e)
            return RegistrationFailure(e)
        }

        logger.atInfo().addKeyValue("UserDN", adUser.dn).log("User successfully created")
        return if (ssoClient?.required == true)
            SSOUserCreated(adUser.cn)
        else
            UserCreated(adUser, setPasswordTokenService.createToken(adUser.cn))
    }

    private suspend fun addUserToDefaultGroups(adUser: UserService.ADUser, call: ApplicationCall) {
        try {
            groupService.addUserToGroup(adUser, DeltaConfig.DATAMART_DELTA_REPORT_USERS, call, null)
            groupService.addUserToGroup(adUser, DeltaConfig.DATAMART_DELTA_USER, call, null)
            logger.atInfo().addKeyValue("UserDN", adUser.dn).log("User added to default groups")
        } catch (e: Exception) {
            logger.atError().addKeyValue("UserDN", adUser.dn).log("Error adding user to default groups", e)
            throw e
        }
    }

    private fun organisationUserGroup(orgCode: String): String {
        return String.format("%s-%s", DeltaConfig.DATAMART_DELTA_USER, orgCode)
    }

    private suspend fun addUserToOrganisations(
        adUser: UserService.ADUser,
        organisations: List<Organisation>,
        call: ApplicationCall
    ) {
        logger.atInfo().addKeyValue("UserDN", adUser.dn).log("Adding user to domain organisations")
        try {
            organisations.forEach {
                if (!it.retired) {
                    groupService.addUserToGroup(
                        adUser,
                        organisationUserGroup(it.code),
                        call,
                        null,
                    )
                    logger.atInfo().addKeyValue("UserDN", adUser.dn)
                        .log("Added user to domain organisation with code {}", it.code)
                } else {
                    logger.info("Organisation {} is retired, with retirement date: {}", it.code, it.retirementDate)
                }
            }
        } catch (e: Exception) {
            logger.atError().addKeyValue("UserDN", adUser.dn).log("Error adding user to domain organisations", e)
            throw e
        }
        logger.atInfo().addKeyValue("UserDN", adUser.dn).log("User added to domain organisations")
    }

    private fun getEmailContacts(adUser: UserService.ADUser): EmailContacts {
        return EmailContacts(
            adUser.mail,
            adUser.getDisplayName(),
            emailConfig
        )
    }

    suspend fun sendRegistrationEmail(registrationResult: RegistrationResult, call: ApplicationCall) {
        when (registrationResult) {
            is UserCreated -> {
                emailService.sendSetPasswordEmail(
                    registrationResult.user.givenName,
                    registrationResult.token,
                    registrationResult.user.cn,
                    null,
                    getEmailContacts(registrationResult.user),
                    call,
                )
            }

            is SSOUserCreated -> {
                // No email sent
            }

            is UserAlreadyExists -> {
                emailService.sendAlreadyAUserEmail(
                    registrationResult.user.givenName,
                    registrationResult.user.cn,
                    getEmailContacts(registrationResult.user),
                )
            }

            is RegistrationFailure -> {
                // No email needs to be sent if the registration fails
            }
        }
    }
}


data class Registration(
    val firstName: String,
    val lastName: String,
    val emailAddress: String,
    val azureObjectId: String? = null,
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
