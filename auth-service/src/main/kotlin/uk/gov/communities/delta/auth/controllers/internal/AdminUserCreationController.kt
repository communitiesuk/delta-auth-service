package uk.gov.communities.delta.auth.controllers.internal

import io.ktor.http.*
import io.ktor.server.application.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import org.slf4j.LoggerFactory
import uk.gov.communities.delta.auth.config.AzureADSSOConfig
import uk.gov.communities.delta.auth.config.EmailConfig
import uk.gov.communities.delta.auth.config.LDAPConfig
import uk.gov.communities.delta.auth.plugins.ApiError
import uk.gov.communities.delta.auth.services.*
import uk.gov.communities.delta.auth.utils.EmailAddressChecker
import java.util.*

class AdminUserCreationController(
    private val ldapConfig: LDAPConfig,
    private val ssoConfig: AzureADSSOConfig,
    private val emailConfig: EmailConfig,
    private val userLookupService: UserLookupService,
    private val userService: UserService,
    private val groupService: GroupService,
    private val emailService: EmailService,
    private val setPasswordTokenService: SetPasswordTokenService,
    private val deltaUserPermissionsRequestMapper: DeltaUserPermissionsRequestMapper,
    private val accessGroupDCLGMembershipUpdateEmailService: AccessGroupDCLGMembershipUpdateEmailService,
) : AdminUserController(userLookupService) {
    private val emailAddressChecker = EmailAddressChecker()
    private val logger = LoggerFactory.getLogger(javaClass)

    fun route(route: Route) {
        route.post { createUser(call) }
    }

    private suspend fun createUser(call: ApplicationCall) {
        // Get calling user from call
        val (session, callingUser) = getSessionAndUserIfUserHasPermittedRole(arrayOf(DeltaSystemRole.ADMIN), call)

        val deltaUserDetailsRequest = call.receive<DeltaUserDetailsRequest>()

        val ssoClient = ssoConfig.ssoClients.firstOrNull {
            deltaUserDetailsRequest.email.lowercase().endsWith(it.emailDomain)
        }
        val adUser = UserService.ADUser(
            ldapConfig,
            deltaUserDetailsRequest,
            ssoClient,
        )

        if (userLookupService.userExists(adUser.cn)) {
            logger.atWarn().addKeyValue("email", adUser.mail).addKeyValue("UserDN", adUser.dn)
                .log("User being made by admin already exists")
            throw ApiError(
                HttpStatusCode.Conflict,
                "user_already_exists",
                "User already exists upon creation by admin",
                "A user with this username already exists, you can edit that user via the users page"
            )
        }
        if (!emailAddressChecker.hasValidFormat(adUser.mail)) {
            logger.atWarn().addKeyValue("email", adUser.mail).addKeyValue("UserDN", adUser.dn)
                .log("Admin tried to create user with invalid email")
            throw ApiError(
                HttpStatusCode.BadRequest,
                "invalid_email",
                "Email address is invalid",
                "This email is invalid. Please check it was entered correctly"
            )
        }
        val userPermissions = try {
            deltaUserPermissionsRequestMapper.deltaRequestToUserPermissions(deltaUserDetailsRequest)
        } catch (e: DeltaUserPermissions.Companion.BadInput) {
            throw ApiError(
                HttpStatusCode.BadRequest,
                "bad_request",
                e.message!!,
                "Requested permissions are invalid: ${e.message}"
            )
        }
        if (userPermissions.roles.contains(DeltaSystemRole.ADMIN)) {
            throw ApiError(
                HttpStatusCode.UnprocessableEntity,
                "admin_role_forbidden",
                "Cannot assign admin role",
                "Cannot assign admin role",
            )
        }

        val userGUID: UUID
        try {
            userGUID = userService.createUser(adUser, ssoClient, session, call)
        } catch (e: Exception) {
            logger.atError().addKeyValue("UserDN", adUser.dn).log("Error creating user", e)
            throw ApiError(
                HttpStatusCode.InternalServerError,
                "error_creating_user",
                "Error creating user",
                "An error occurred while creating the user, please try again"
            )
        }
        logger.atInfo().addKeyValue("UserDN", adUser.dn).log("User successfully created")
        try {
            userPermissions.getADGroupCNs().forEach {
                groupService.addUserToGroup(adUser, userGUID, it, call, session)
            }
        } catch (e: Exception) {
            logger.atError().addKeyValue("UserDN", adUser.dn).log("Error adding user to groups", e)
            throw ApiError(
                HttpStatusCode.InternalServerError,
                "error_adding_user_to_groups",
                "Error adding user to groups",
                "The user was created but the details were not saved correctly, please find and edit the user to have the desired details."
            )
        }
        logger.atInfo().addKeyValue("UserDN", adUser.dn).log("User successfully added to all desired groups")

        if (ssoClient?.required == true) {
            logger.atInfo().addKeyValue("UserDN", adUser.dn).log("SSO user created by admin, no email sent")
            return call.respond(mapOf("message" to "User created. Single Sign On (SSO) is enabled for this user based on their email domain. The account has been activated automatically, no email has been sent."))
        }
        try {
            emailService.sendSetPasswordEmail(
                adUser.givenName,
                setPasswordTokenService.createToken(adUser.cn),
                adUser.cn,
                userGUID,
                session,
                EmailContacts(adUser.mail, adUser.getDisplayName(), emailConfig),
                call
            )
        } catch (e: Exception) {
            throw ApiError(
                HttpStatusCode.InternalServerError,
                "error_sending_email",
                "Error sending new user email",
                "The user was made successfully but the activation email failed to send, please find the user and send a new activation email"
            )
        }

        accessGroupDCLGMembershipUpdateEmailService.sendNotificationEmailsForChangeToUserAccessGroups(
            AccessGroupDCLGMembershipUpdateEmailService.UpdatedUser(adUser.mail, "${adUser.givenName} ${adUser.sn}"),
            callingUser,
            emptyList(),
            userPermissions.accessGroups
        )

        return call.respond(mapOf("message" to "User created successfully"))
    }
}
