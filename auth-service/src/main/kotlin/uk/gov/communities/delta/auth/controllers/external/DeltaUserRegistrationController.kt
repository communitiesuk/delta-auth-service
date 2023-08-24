package uk.gov.communities.delta.auth.controllers.external

import OrganisationService
import io.ktor.server.application.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import io.ktor.server.thymeleaf.*
import org.slf4j.LoggerFactory
import uk.gov.communities.delta.auth.config.DeltaConfig
import uk.gov.communities.delta.auth.utils.EmailAddressChecker
import uk.gov.communities.delta.auth.utils.Registration
import uk.gov.communities.delta.auth.utils.RegistrationService

class DeltaUserRegistrationController(
    private val deltaConfig: DeltaConfig,
    organisationService: OrganisationService,
    private val registrationService: RegistrationService,
) {
    private val logger = LoggerFactory.getLogger(this.javaClass)
    private val emailAddressChecker = EmailAddressChecker(organisationService)

    fun registerRoutes(route: Route) {
        route.post {
            registerPost(call)
        }
        route.get {
            registerGet(call)
        }
    }

    private suspend fun registerGet(call: ApplicationCall) {
        call.respondRegisterPage()
    }

    private val firstNameEmpty = "First name must not be empty"
    private val lastNameEmpty = "Last name must not be empty"
    private val emailAddressEmpty = "Email address must not be empty"
    private val confirmEmailAddressEmpty = "Confirm email address must not be empty"
    private val notEqualEmails = "Email addresses do not match"
    private val notAnEmailAddress = "Email address must be a valid email address"
    private val notAKnownDomain = "Email address domain not recognised, please use an email address associated with an organisation using DELTA or Contact Us"

    private suspend fun registerPost(call: ApplicationCall) {
        val formParameters = call.receiveParameters()
        val firstName = formParameters["firstName"].orEmpty()
        val lastName = formParameters["lastName"].orEmpty()
        val emailAddress = formParameters["emailAddress"].orEmpty()
        val confirmEmailAddress = formParameters["confirmEmailAddress"].orEmpty()

        val firstNameErrors = ArrayList<String>()
        val lastNameErrors = ArrayList<String>()
        val emailAddressErrors = ArrayList<String>()
        val confirmEmailAddressErrors = ArrayList<String>()

        if (firstName.isEmpty()) firstNameErrors.add(firstNameEmpty)
        if (lastName.isEmpty()) lastNameErrors.add(lastNameEmpty)
        if (emailAddress.isEmpty()) emailAddressErrors.add(emailAddressEmpty)
        else {
            if (!emailAddressChecker.hasValidEmailFormat(emailAddress)) emailAddressErrors.add(notAnEmailAddress)
            else if (!emailAddressChecker.hasKnownDomain(emailAddress)) emailAddressErrors.add(notAKnownDomain)
        }
        if (confirmEmailAddress.isEmpty()) confirmEmailAddressErrors.add(confirmEmailAddressEmpty)
        else if (confirmEmailAddress != emailAddress) confirmEmailAddressErrors.add(notEqualEmails)

        if (firstNameErrors.isNotEmpty() || lastNameErrors.isNotEmpty() || emailAddressErrors.isNotEmpty() || confirmEmailAddressErrors.isNotEmpty()) {
            return call.respondRegisterPage(
                firstNameErrors,
                lastNameErrors,
                emailAddressErrors,
                confirmEmailAddressErrors,
                firstName,
                lastName,
                emailAddress,
                confirmEmailAddress
            )
        } else {
            val registration = Registration(firstName, lastName, emailAddress)
            try {
                registrationService.register(registration)
            } catch (ex: Exception) {
                logger.error("Error registering user", ex) // TODO - improve error messages
                return call.respondRegisterPage(
                    firstNameErrors,
                    lastNameErrors,
                    emailAddressErrors,
                    confirmEmailAddressErrors,
                    firstName,
                    lastName,
                    emailAddress,
                    confirmEmailAddress
                )
            }
            return call.respondSuccessPage()
        }
    }

    private suspend fun ApplicationCall.respondRegisterPage(
        firstNameErrors: ArrayList<String> = ArrayList<String>(),
        lastNameErrors: ArrayList<String> = ArrayList<String>(),
        emailAddressErrors: ArrayList<String> = ArrayList<String>(),
        confirmEmailAddressErrors: ArrayList<String> = ArrayList<String>(),
        firstName: String = "",
        lastName: String = "",
        emailAddress: String = "",
        confirmEmailAddress: String = ""
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

    private suspend fun ApplicationCall.respondSuccessPage() = respond(
        ThymeleafContent(
            "registration-success",
            mapOf(
                "deltaUrl" to deltaConfig.deltaWebsiteUrl,
            )
        )
    )

}