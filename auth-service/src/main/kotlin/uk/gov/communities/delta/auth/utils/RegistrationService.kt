package uk.gov.communities.delta.auth.utils

import OrganisationService
import org.slf4j.LoggerFactory
import uk.gov.communities.delta.auth.config.DeltaConfig

class RegistrationService(
    private val deltaConfig: DeltaConfig,
    private val organisationService: OrganisationService,
    private val emailService: EmailService
) {
    class RegistrationResult {
        enum class Status {
            CREATED, ALREADY_EXISTS, OTHER_FAILURE
        }

        val status: Status
        val email: String
        val token: String?

        constructor(
            status: Status,
            email: String
        ) {
            this.status = status
            this.email = email
            token = null
        }

        constructor(
            status: Status,
            email: String,
            token: String
        ) {
            this.status = status
            this.email = email
            this.token = token // TODO - are these still needed with tokens stored in db (see below)
        }
    }

    // Previously users could be datamart users but not delta users, at migration we only transferred over users who
    // were delta users so there should never be users who exist but aren't delta users - therefore can remove all logic
    // for attaching users and checking if they are indeed delta users (if they somehow existed they'd get a "contact
    // the service desk" error at login which is what we want


    private val logger = LoggerFactory.getLogger(javaClass)
    private val userService = UserService()

    //        val context = Context(Locale.getDefault(), model) TODO - what did this do? Is it still needed? - from email sending


    fun register(registration: Registration): RegistrationResult { // TODO - does this still need to return anything?
        val user = userService.findUserById(registration.emailAddress, true).orElse(null)
        if (user != null) {
            // TODO - logic check - do we want this to happen?
            //  - if a user exists already then registering them again will add them to organisations associated with their domain
            //      - can't see a scenario where this isn't already the case but if it is then do we definitely want to fix it?
//            registrationOrganisationService.attachUserToDomainOrganisations(user)
            // TODO - set this up to send an email (bring email content over from delta)
//            deltaUserEmailService.sendEmail(user::getEmail)
            return RegistrationResult(
                RegistrationResult.Status.ALREADY_EXISTS,
                registration.emailAddress
            )
        }
//        TODO - implement creation of users as before (ish) for non-SSO
//             - for SSO users (add domain check) - implement different create user route (no need for password)
//                    - does this need to come via register page in the same way?
//                    - is their account just created automatically on first log in or do they still have to register?
//        registrationUserService.createUser(registration)

//        TODO - add new user to necessary organisations (same for SSO creation and not-SSO creation)
//        registrationOrganisationService.attachUserToDomainOrganisations(registration)

//        TODO - get value for setPasswordUrl (if not SSO person)
//              - create table in database for reset password tokens
//                  - containing: user CN, token, timestamp
//                  - watch for timing attacks on comparison of tokens
//              - add row to table containing token
//              - send email containing url as before (ensure url encoding happens where necessary)
//              - compare token to tokens in the database on set password
//              - implement the rest of set password
//                  - removing nunjucks
//                  - remove unnecessary code e.g. for reset rather than set etc
//        val request: ForgotPasswordRequest = registration.emailAddress
//        val result: ForgotPasswordResult = passwordService.forgotPassword(request)
//        if (!result.isSuccessful()) return RegistrationResult(
//            RegistrationResult.Status.OTHER_FAILURE,
//            registration.emailAddress!!
//        )
        emailService.sendTemplateEmail(
            "new-user-email",
            registration.emailAddress,
            "testFromEmail@softwire.com", // TODO - make these environment variables?
            "Test From Email",
            "testReplyTo@softwire.com",
            "Test Reply To Email",
            "DLUHC DELTA - New User Account",
            mapOf(
                "deltaUrl" to deltaConfig.deltaWebsiteUrl,
                "userFirstName" to registration.firstName,
//                    "setPasswordUrl" to setPasswordUrl
            )
        )
        return RegistrationResult(
            RegistrationResult.Status.CREATED,
            registration.emailAddress,
//            result.getToken() - TODO - what was this used for? Is it the password reset token
        )
    }

    // TODO - fix below functions if needed else delete them

//    fun attachUserToDomainOrganisations(user: User) {
//        val email: String = user.getEmail()
//        val domainOrgs = domainOrgs(email, user.getOrganisationIds())
//        userOrganisationService.addUserToOrganisations(email, domainOrgs)
//    }

//    fun attachUserToDomainOrganisations(registration: Registration) {
//        val email: String = registration.getEmailAddress()
//        val domainOrgs = domainOrgs(email)
//        logger.info("attachUserToDomainOrganisations number of domainOrgs: {}", domainOrgs.size)
//        domainOrgs.forEach(Consumer { msg: String? -> logger.debug(msg) })
//        userOrganisationService.addUserToOrganisations(email, domainOrgs)
//    }

//    private fun domainOrgs(email: String, excludes: List<String> = emptyList()): List<String> {
//        val orgIds = ImmutableList.builder<String>()
//        val filter =
//            Predicate { s: String ->
//                !Strings.isNullOrEmpty(
//                    s
//                ) && !excludes.contains(s)
//            }
//        val addOrgs: Consumer<List<Organisation?>> =
//            Consumer<List<Organisation?>> { orgs: List<Organisation?> ->
//                orgs.stream()
//                    .map<Any>(Organisation::getCode)
//                    .filter(filter)
//                    .forEach(orgIds::add)
//            }
//        findDomain(email)
//            .map<Any>(organisationService::getOrganisationsByDomain)
//            .ifPresent(addOrgs)
//        return orgIds.build()
//    }
}

class Registration(
    val firstName: String,
    val lastName: String,
    val emailAddress: String
) {}