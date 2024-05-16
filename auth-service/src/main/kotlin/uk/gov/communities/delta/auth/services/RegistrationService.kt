package uk.gov.communities.delta.auth.services

import io.ktor.server.application.*
import io.ktor.server.auth.*
import org.slf4j.LoggerFactory
import uk.gov.communities.delta.auth.config.AzureADSSOClient
import uk.gov.communities.delta.auth.config.DeltaConfig
import uk.gov.communities.delta.auth.config.EmailConfig
import uk.gov.communities.delta.auth.config.LDAPConfig
import uk.gov.communities.delta.auth.repositories.LdapUser
import java.util.*

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
    class UserCreated(val user: LdapUser, val token: String) : RegistrationResult()
    class SSOUserCreated(val userCN: String, val userGUID: UUID) : RegistrationResult()
    class UserAlreadyExists(val user: LdapUser) : RegistrationResult()
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

        when (val user = userLookupService.userIfUserWithEmailExists(adUser.mail)) {
            is LdapUser -> {
                logger.atWarn().addKeyValue("UserDN", adUser.dn).log("User tried to register but user already exists")
                return UserAlreadyExists(user)
            }
        }
        val user: LdapUser
        try {
            user = userService.createUser(adUser, ssoClient, call.principal<OAuthSession>(), call, azureObjectId)
            addUserToDefaultGroups(user, call)
            addUserToOrganisations(user, organisations, call)
        } catch (e: Exception) {
            logger.atError().addKeyValue("UserDN", adUser.dn).log("Error creating user", e)
            return RegistrationFailure(e)
        }

        logger.atInfo().addKeyValue("UserDN", user.dn).log("User successfully created")
        return if (ssoClient?.required == true)
            SSOUserCreated(user.cn, user.getUUID())
        else
            UserCreated(user, setPasswordTokenService.createToken(user.cn, user.getUUID()))
    }

    private suspend fun addUserToDefaultGroups(user: LdapUser, call: ApplicationCall) {
        try {
            groupService.addUserToGroup(
                user, DeltaConfig.DATAMART_DELTA_REPORT_USERS, call, null, userLookupService,
            )
            groupService.addUserToGroup(
                user, DeltaConfig.DATAMART_DELTA_USER, call, null, userLookupService
            )
            logger.atInfo().addKeyValue("UserDN", user.dn).log("User added to default groups")
        } catch (e: Exception) {
            logger.atError().addKeyValue("UserDN", user.dn).log("Error adding user to default groups", e)
            throw e
        }
    }

    private fun organisationUserGroup(orgCode: String): String {
        return String.format("%s-%s", DeltaConfig.DATAMART_DELTA_USER, orgCode)
    }

    private suspend fun addUserToOrganisations(
        user: LdapUser,
        organisations: List<Organisation>,
        call: ApplicationCall
    ) {
        logger.atInfo().addKeyValue("UserDN", user.dn).log("Adding user to domain organisations")
        try {
            organisations.forEach {
                if (!it.retired) {
                    groupService.addUserToGroup(
                        user,
                        organisationUserGroup(it.code),
                        call,
                        null,
                        userLookupService,
                    )
                    logger.atInfo().addKeyValue("UserDN", user.dn)
                        .log("Added user to domain organisation with code {}", it.code)
                } else {
                    logger.info("Organisation {} is retired, with retirement date: {}", it.code, it.retirementDate)
                }
            }
        } catch (e: Exception) {
            logger.atError().addKeyValue("UserDN", user.dn).log("Error adding user to domain organisations", e)
            throw e
        }
        logger.atInfo().addKeyValue("UserDN", user.dn).log("User added to domain organisations")
    }

    private fun getEmailContacts(user: LdapUser): EmailContacts {
        return EmailContacts(
            user.email!!,
            user.fullName,
            emailConfig
        )
    }

    suspend fun sendRegistrationEmail(registrationResult: RegistrationResult, call: ApplicationCall) {
        when (registrationResult) {
            is UserCreated -> {
                emailService.sendSetPasswordEmail(
                    registrationResult.user.firstName,
                    registrationResult.token,
                    registrationResult.user.cn,
                    registrationResult.user.getUUID(),
                    null,
                    userLookupService,
                    getEmailContacts(registrationResult.user),
                    call,
                )
            }

            is SSOUserCreated -> {
                // No email sent
            }

            is UserAlreadyExists -> {
                emailService.sendAlreadyAUserEmail(
                    registrationResult.user.firstName,
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
