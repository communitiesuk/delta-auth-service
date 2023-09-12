package uk.gov.communities.delta.auth.services

import OrganisationService
import org.slf4j.LoggerFactory
import uk.gov.communities.delta.auth.config.DeltaConfig
import uk.gov.communities.delta.auth.config.EmailConfig
import uk.gov.communities.delta.auth.config.LDAPConfig
import uk.gov.communities.delta.auth.utils.ADUser
import uk.gov.communities.delta.auth.utils.emailToDomain

class RegistrationService(
    private val deltaConfig: DeltaConfig,
    private val emailConfig: EmailConfig,
    private val ldapConfig: LDAPConfig,
    private val organisationService: OrganisationService,
    private val emailService: EmailService,
    private val newUserService: NewUserService,
    private val userLookupService: UserLookupService,
) {
    sealed class RegistrationResult
    class UserCreated(val registration: Registration, val token: String) : RegistrationResult()
    class UserAlreadyExists(val registration: Registration) : RegistrationResult()
    class RegistrationFailure(val exception: Exception?) : RegistrationResult()

    // Previously users could be datamart users but not delta users, at migration we only transferred over users who
    // were delta users so there should never be users who exist but aren't delta users - therefore can remove all logic
    // for attaching users and checking if they are indeed delta users (if they somehow existed they'd get a "contact
    // the service desk" error at login which is what we want

    private val logger = LoggerFactory.getLogger(javaClass) // TODO - add logs where useful

    suspend fun register(registration: Registration): RegistrationResult {
        val adUser = ADUser(registration, ldapConfig)
        if (userLookupService.userExists(adUser.cn)) {
            return UserAlreadyExists(registration)
        }

//        TODO - for SSO users (add domain check) - implement different create user route (no need for password)
//                    - does this need to come via register page in the same way?
//                    - is their account just created automatically on first log in or do they still have to register?
//                          - If people log in via SSO and don't have a delta account yet then we make them a delta account and redirect them to delta logged into that account
//                          - If people attempt to register for delta with an email that is one of the SSO required org domains then we redirect them to SSO and once they have logged in treat it as above

        newUserService.createUser(adUser)

        addUserToDefaultGroups(adUser)

        addUserToDomainOrganisations(adUser)

//        TODO - get value for setPasswordUrl (if not SSO person)
//              - create table in database for reset password tokens
//                  - containing: user CN, token, timestamp
//                  - watch for timing attacks on comparison of tokens
//              - add row to table containing token
//              - send email containing url as before (ensure url encoding happens where necessary)
//              - compare token to tokens in the database on set password
//              - make sure each token can only be used once!
//              - implement the rest of set password
//                  - removing nunjucks
//                  - remove unnecessary code e.g. for reset rather than set etc
//        val request: ForgotPasswordRequest = registration.emailAddress
//        val result: ForgotPasswordResult = passwordService.forgotPassword(request)
//        if (!result.isSuccessful()) return RegistrationResult(
//            RegistrationResult.Status.OTHER_FAILURE,
//            registration.emailAddress!!
//        )

        return UserCreated(registration, "tokenOrUrl") //TODO - token
    }

    private fun addUserToDefaultGroups(adUser: ADUser) {
        try {
            newUserService.addUserToGroup(adUser, deltaConfig.datamartDeltaReportUsers)
            newUserService.addUserToGroup(adUser, deltaConfig.datamartDeltaUser)
        } catch (e: Exception) {
            logger.error("Issue adding member to group: {}", e.toString())
            throw e
        }
    }

    private fun organisationUserGroup(orgCode: String): String {
        return String.format("%s-%s", deltaConfig.datamartDeltaUser, orgCode)
    }

    private suspend fun addUserToDomainOrganisations(adUser: ADUser) {
        val organisations = organisationService.findAllByDomain(
            emailToDomain(adUser.mail)
        )

        try {
            organisations.forEach {
                if (!it.retired)
                    newUserService.addUserToGroup(
                        adUser,
                        organisationUserGroup(it.code)
                    )
            }

        } catch (e: Exception) {
            throw e // TODO
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
        when (registrationResult) {
            is UserCreated -> {
                emailService.sendTemplateEmail(
                    "new-user",
                    getRegistrationEmailContacts(registrationResult.registration),
                    "DLUHC DELTA - New User Account",
                    mapOf(
                        "deltaUrl" to deltaConfig.deltaWebsiteUrl,
                        "userFirstName" to registrationResult.registration.firstName,
//                    "setPasswordUrl" to setPasswordUrl // TODO - from token
                    )
                )
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
                // TODO - complete this
            }
        }
    }
}

class Registration(
    val firstName: String,
    val lastName: String,
    val emailAddress: String
)