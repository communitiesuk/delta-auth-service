package uk.gov.communities.delta.auth.controllers.external

import io.ktor.http.*
import io.ktor.server.application.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import io.ktor.server.thymeleaf.*
import org.slf4j.LoggerFactory
import uk.gov.communities.delta.auth.config.AuthServiceConfig
import uk.gov.communities.delta.auth.config.AzureADSSOConfig
import uk.gov.communities.delta.auth.config.DeltaConfig
import uk.gov.communities.delta.auth.deltaRouteWithEmail
import uk.gov.communities.delta.auth.services.*
import uk.gov.communities.delta.auth.utils.EmailAddressChecker
import uk.gov.communities.delta.auth.utils.emailToDomain

class DeltaUserRegistrationController(
    private val deltaConfig: DeltaConfig,
    private val authServiceConfig: AuthServiceConfig,
    private val ssoConfig: AzureADSSOConfig,
    private val organisationService: OrganisationService,
    private val registrationService: RegistrationService,
) {
    private val logger = LoggerFactory.getLogger(this.javaClass)
    private val emailAddressChecker = EmailAddressChecker()

    fun registerFormRoutes(route: Route) {
        route.post {
            registerPost(call)
        }
        route.get {
            registerGet(call)
        }
    }

    fun registerSuccessRoute(route: Route) {
        route.get {
            call.respond(
                ThymeleafContent(
                    "registration-success",
                    mapOf(
                        "deltaUrl" to deltaConfig.deltaWebsiteUrl,
                        "emailAddress" to call.parameters["emailAddress"]!!,
                    )
                )
            )
        }
    }

    private suspend fun registerGet(call: ApplicationCall) {
        call.respondRegisterPage()
    }

    private val firstNameEmpty = "First name must not be empty"
    private val lastNameEmpty = "Last name must not be empty"
    private val firstNameContainsDisallowedCharacters =
        "First name must not contain special characters <, >, \", =, or &"
    private val lastNameContainsDisallowedCharacters = "Last name must not contain special characters <, >, \", =, or &"
    private val emailContainsDisallowedCharacters = "Email must not contain special characters <, >, \", =, or &"
    private val emailAddressEmpty = "Email address must not be empty"
    private val confirmEmailAddressEmpty = "Confirm email address must not be empty"
    private val notEqualEmails = "Email addresses do not match"
    private val notAnEmailAddress = "Email address must be a valid email address"
    private val notAKnownDomain =
        "Email address domain not recognised, please use an email address associated with an organisation using DELTA. Please contact the service desk if you think this should have worked."

    private suspend fun registerPost(call: ApplicationCall) {
        val formParameters = call.receiveParameters()
        val firstName = formParameters["firstName"].orEmpty()
        val lastName = formParameters["lastName"].orEmpty()
        val emailAddress = formParameters["emailAddress"].orEmpty().lowercase()
        val confirmEmailAddress = formParameters["confirmEmailAddress"].orEmpty().lowercase()

        val firstNameErrors = ArrayList<String>()
        val lastNameErrors = ArrayList<String>()
        val emailAddressErrors = ArrayList<String>()
        val confirmEmailAddressErrors = ArrayList<String>()

        if (firstName.isEmpty()) firstNameErrors.add(firstNameEmpty)
        if (lastName.isEmpty()) lastNameErrors.add(lastNameEmpty)

        // Delta has had issues with XSS in the past, so we disallow these characters as an extra precaution
        if (hasDisallowedSpecialCharacters(firstName)) firstNameErrors.add(firstNameContainsDisallowedCharacters)
        if (hasDisallowedSpecialCharacters(lastName)) lastNameErrors.add(lastNameContainsDisallowedCharacters)
        if (hasDisallowedSpecialCharacters(emailAddress)) emailAddressErrors.add(emailContainsDisallowedCharacters)

        var organisations: List<Organisation> = listOf()
        if (emailAddress.isEmpty()) emailAddressErrors.add(emailAddressEmpty)
        else {
            if (!emailAddressChecker.hasValidFormat(emailAddress)) emailAddressErrors.add(notAnEmailAddress)
            else {
                organisations = organisationService.findAllByDomain(emailToDomain(emailAddress))
                if (!emailAddressChecker.hasKnownNotRetiredDomain(organisations)) emailAddressErrors.add(
                    notAKnownDomain
                )
            }
        }
        if (confirmEmailAddress.isEmpty()) confirmEmailAddressErrors.add(confirmEmailAddressEmpty)
        else if (confirmEmailAddress != emailAddress) confirmEmailAddressErrors.add(notEqualEmails)

        if (hasErrors(firstNameErrors, lastNameErrors, emailAddressErrors, confirmEmailAddressErrors)) {
            return call.respondRegisterPage(
                firstName,
                lastName,
                emailAddress,
                confirmEmailAddress,
                firstNameErrors,
                lastNameErrors,
                emailAddressErrors,
                confirmEmailAddressErrors
            )
        } else {
            val ssoClientMatchingEmailDomain = ssoConfig.ssoClients.firstOrNull {
                it.required && emailAddress.lowercase().endsWith(it.emailDomain)
            }
            if (ssoClientMatchingEmailDomain != null) {
                return call.respondRedirect(
                    deltaRouteWithEmail(
                        deltaConfig.deltaWebsiteUrl,
                        ssoClientMatchingEmailDomain.internalId,
                        emailAddress
                    )
                )
            }

            val registration = Registration(firstName, lastName, emailAddress)
            val registrationResult = try {
                registrationService.register(registration, organisations)
            } catch (e: Exception) {
                logger.error(
                    "Error registering user with  name: {} {}, email address: {}",
                    firstName,
                    lastName,
                    emailAddress,
                    e
                )
                throw e
            }
            try {
                registrationService.sendRegistrationEmail(registrationResult)
            } catch (e: Exception) {
                logger.error(
                    "Error sending email after registration for first name: {}, last name: {}, email address: {}. Result of registration was {}",
                    firstName,
                    lastName,
                    emailAddress,
                    getResultTypeString(registrationResult),
                    e
                )
                throw e
            }
            return call.respondToResult(registrationResult)
        }
    }

    private fun hasErrors(
        firstNameErrors: ArrayList<String>,
        lastNameErrors: ArrayList<String>,
        emailAddressErrors: ArrayList<String>,
        confirmEmailAddressErrors: ArrayList<String>
    ): Boolean {
        return arrayOf(
            firstNameErrors,
            lastNameErrors,
            emailAddressErrors,
            confirmEmailAddressErrors
        ).any { it.isNotEmpty() }
    }

    private fun hasDisallowedSpecialCharacters(word: String): Boolean {
        return word.contains("[<>\"=&]")
    }

    private suspend fun ApplicationCall.respondToResult(registrationResult: RegistrationService.RegistrationResult) {
        return when (registrationResult) {
            is RegistrationService.UserCreated -> {
                respondSuccessPage(registrationResult.registration.emailAddress)
            }

            is RegistrationService.SSOUserCreated -> {
                // Never happens
            }

            is RegistrationService.UserAlreadyExists -> {
                respondSuccessPage(registrationResult.registration.emailAddress)
            }

            is RegistrationService.RegistrationFailure -> {
                throw registrationResult.exception
            }
        }
    }

    private suspend fun ApplicationCall.respondSuccessPage(emailAddress: String) =
        respondRedirect(authServiceConfig.serviceUrl + "/delta/register/success?emailAddress=${emailAddress.encodeURLParameter()}")

    private suspend fun ApplicationCall.respondRegisterPage(
        firstName: String = "",
        lastName: String = "",
        emailAddress: String = "",
        confirmEmailAddress: String = "",
        firstNameErrors: ArrayList<String> = ArrayList(),
        lastNameErrors: ArrayList<String> = ArrayList(),
        emailAddressErrors: ArrayList<String> = ArrayList(),
        confirmEmailAddressErrors: ArrayList<String> = ArrayList()
    ) {
        val errors = ArrayList<ArrayList<String>>()
        firstNameErrors.forEach { message ->
            errors.add(arrayListOf(message, "#firstName"))
        }
        lastNameErrors.forEach { message ->
            errors.add(arrayListOf(message, "#lastName"))
        }
        emailAddressErrors.forEach { message ->
            errors.add(arrayListOf(message, "#emailAddress"))
        }
        confirmEmailAddressErrors.forEach { message ->
            errors.add(arrayListOf(message, "#confirmEmailAddress"))
        }
        respond(
            ThymeleafContent(
                "register-user-form",
                mapOf(
                    "deltaUrl" to deltaConfig.deltaWebsiteUrl,
                    "allErrors" to errors,
                    "firstNameErrorMessages" to firstNameErrors,
                    "firstName" to firstName,
                    "lastNameErrorMessages" to lastNameErrors,
                    "lastName" to lastName,
                    "emailAddressErrorMessages" to emailAddressErrors,
                    "emailAddress" to emailAddress,
                    "confirmEmailErrorMessages" to confirmEmailAddressErrors,
                    "confirmEmailAddress" to confirmEmailAddress,
                )
            )
        )
    }
}
