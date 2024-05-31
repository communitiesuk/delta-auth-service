package uk.gov.communities.delta.auth.controllers.internal

import io.ktor.http.*
import io.ktor.server.application.*
import io.ktor.server.response.*
import org.slf4j.LoggerFactory
import uk.gov.communities.delta.auth.config.AzureADSSOConfig
import uk.gov.communities.delta.auth.plugins.ApiError
import uk.gov.communities.delta.auth.repositories.LdapUser
import uk.gov.communities.delta.auth.services.*
import uk.gov.communities.delta.auth.utils.getUserFromCallParameters
import uk.gov.communities.delta.auth.utils.randomBase64

class AdminEnableDisableUserController(
    private val ssoConfig: AzureADSSOConfig,
    private val userLookupService: UserLookupService,
    private val userGUIDMapService: UserGUIDMapService,
    private val userService: UserService,
    private val setPasswordTokenService: SetPasswordTokenService,
    private val auditService: UserAuditService,
) : AdminUserController(userLookupService) {

    private val logger = LoggerFactory.getLogger(javaClass)

    private val allowedRoles = arrayOf(DeltaSystemRole.ADMIN, DeltaSystemRole.READ_ONLY_ADMIN)

    suspend fun enableUser(call: ApplicationCall) {
        val session = getSessionIfUserHasPermittedRole(allowedRoles, call)

        val user = getUserFromCallParameters(
            call.parameters,
            userLookupService,
            userGUIDMapService,
            "Something went wrong enabling the user, please try again",
            "enable_user"
        )

        if (user.accountEnabled) {
            return call.respond(mapOf("message" to "Account already enabled"))
        }

        if (user.passwordLastSet == null) {
            if (user.isSSORequiredUser()) {
                logger.atInfo().addKeyValue("targetUserGUID", user.getGUID())
                    .log("Setting random password and enabling SSO user")
                userService.setPasswordAndEnable(user.dn, randomBase64(18))
                auditService.userEnableAudit(user.getGUID(), session.userGUID, call)
                return call.respond(mapOf("message" to "User ${user.email} enabled"))
            } else {
                throw ApiError(
                    HttpStatusCode.BadRequest,
                    "cannot_enable_user_no_password",
                    "User ${user.getGUID()} pwdLastSet is null, will not enable",
                    "User '${user.email}' does not have a password set and so cannot be enabled. Send them an activation email instead.",
                )
            }
        }

        logger.atInfo().addKeyValue("targetUserGUID", user.getGUID()).log("Enabling user")
        userService.enableAccountAndNotifications(user.dn)
        auditService.userEnableAudit(user.getGUID(), session.userGUID, call)

        return call.respond(mapOf("message" to "User ${user.email} enabled"))
    }


    suspend fun disableUser(call: ApplicationCall) {
        val session = getSessionIfUserHasPermittedRole(allowedRoles, call)

        val user = getUserFromCallParameters(
            call.parameters,
            userLookupService,
            userGUIDMapService,
            "Something went wrong disabling the user, please try again",
            "disable_user"
        )

        if (!user.accountEnabled) {
            return call.respond(mapOf("message" to "Account already disabled"))
        }

        logger.atInfo().addKeyValue("targetUserGUID", user.getGUID()).log("Disabling user")
        userService.disableAccountAndNotifications(user.dn)
        auditService.userDisableAudit(user.getGUID(), session.userGUID, call)
        // Clear any set password tokens so that they can't re-enable their account themselves
        setPasswordTokenService.clearTokenForUserGUID(user.getGUID())

        return call.respond(mapOf("message" to "User ${user.email} disabled"))
    }

    private fun LdapUser.isSSORequiredUser(): Boolean {
        return ssoConfig.ssoClients.any { it.required && email?.endsWith(it.emailDomain) == true }
    }
}
