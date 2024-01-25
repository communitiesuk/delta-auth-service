package uk.gov.communities.delta.auth.controllers.internal

import com.fasterxml.jackson.databind.ObjectMapper
import io.ktor.http.*
import io.ktor.server.application.*
import io.ktor.server.auth.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import org.slf4j.LoggerFactory
import uk.gov.communities.delta.auth.config.AzureADSSOConfig
import uk.gov.communities.delta.auth.config.DeltaConfig
import uk.gov.communities.delta.auth.config.EmailConfig
import uk.gov.communities.delta.auth.config.LDAPConfig
import uk.gov.communities.delta.auth.plugins.ApiError
import uk.gov.communities.delta.auth.services.*

class AdminUserCreationController(
    private val ldapConfig: LDAPConfig,
    private val deltaConfig: DeltaConfig,
    private val ssoConfig: AzureADSSOConfig,
    private val emailConfig: EmailConfig,
    private val userLookupService: UserLookupService,
    private val userService: UserService,
    private val groupService: GroupService,
    private val emailService: EmailService,
    private val setPasswordTokenService: SetPasswordTokenService,
) {

    private val logger = LoggerFactory.getLogger(javaClass)

    fun route(route: Route) {
        route.post { createUser(call) }
    }

    private suspend fun createUser(call: ApplicationCall) {
        // Get calling user from call
        val session = call.principal<OAuthSession>()!!
        val callingUser = userLookupService.lookupUserByCn(session.userCn)

        // Authenticate calling user
        val adminGroupCN = LDAPConfig.DATAMART_DELTA_PREFIX + "admin"
        if (!callingUser.memberOfCNs.any { adminGroupCN == it }) {
            throw ApiError(
                HttpStatusCode.Forbidden,
                "forbidden",
                "User trying to create a new user is not an admin",
                "You do not have the permissions to create a user"
            )
        }

        val deltaUserDetails = call.receive<UserService.DeltaUserDetails>()

        val ssoClient = ssoConfig.ssoClients.firstOrNull {
            deltaUserDetails.email.lowercase().endsWith(it.emailDomain)
        }
        val adUser = UserService.ADUser(
            ldapConfig,
            deltaUserDetails,
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
        try {
            userService.createUser(adUser, ssoClient, session, call)
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
            groupService.addUserToGroup(adUser, deltaConfig.datamartDeltaUser, call, session)
            deltaUserDetails.organisations.forEach { orgCode: String ->
                groupService.addUserToGroup(
                    adUser,
                    String.format("%s-%s", deltaConfig.datamartDeltaUser, orgCode),
                    call,
                    session
                )
            }
            deltaUserDetails.accessGroups.forEach { accessGroup ->
                groupService.addUserToGroup(adUser, accessGroup, call, session)
            }
            deltaUserDetails.accessGroupDelegates.forEach { accessGroup ->
                val delegateAccessGroup = makeDelegate(accessGroup)
                groupService.addUserToGroup(adUser, delegateAccessGroup, call, session)
            }
            deltaUserDetails.accessGroupOrganisations.forEach { (accessGroup, organisations) ->
                organisations.forEach { orgCode ->
                    groupService.addUserToGroup(adUser, String.format("%s-%s", accessGroup, orgCode), call, session)
                }
            }
            deltaUserDetails.roles.forEach { role ->
                groupService.addUserToGroup(adUser, role, call, session)
                deltaUserDetails.organisations.forEach { orgCode ->
                    groupService.addUserToGroup(adUser, String.format("%s-%s", role, orgCode), call, session)
                }
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
            return call.respond(mapOf("message" to "SSO user created, no email has been sent to the user since emails aren't sent to SSO users"))
        }
        try {
            emailService.sendSetPasswordEmail(
                adUser.givenName,
                setPasswordTokenService.createToken(adUser.cn),
                adUser.cn,
                call.principal<OAuthSession>()!!,
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

        return call.respond(mapOf("message" to "User created successfully"))
    }

    private fun makeDelegate(accessGroup: String): String {
        return LDAPConfig.DATAMART_DELTA_PREFIX + "delegate-" + accessGroup.substringAfter(LDAPConfig.DATAMART_DELTA_PREFIX)
    }
}