package uk.gov.communities.delta.auth.controllers.internal

import io.ktor.http.*
import io.ktor.server.application.*
import io.ktor.server.response.*
import io.ktor.server.util.*
import org.slf4j.LoggerFactory
import uk.gov.communities.delta.auth.config.AzureADSSOConfig
import uk.gov.communities.delta.auth.config.LDAPConfig.Companion.VALID_USERNAME_REGEX
import uk.gov.communities.delta.auth.plugins.ApiError
import uk.gov.communities.delta.auth.repositories.LdapUser
import uk.gov.communities.delta.auth.services.*
import uk.gov.communities.delta.auth.utils.randomBase64
import javax.naming.NameNotFoundException

class AdminEnableDisableUserController(
    private val ssoConfig: AzureADSSOConfig,
    private val userLookupService: UserLookupService,
    private val userService: UserService,
    private val setPasswordTokenService: SetPasswordTokenService,
    private val auditService: UserAuditService,
) : AdminUserController(userLookupService) {

    private val logger = LoggerFactory.getLogger(javaClass)

    private val allowedRoles = arrayOf(DeltaSystemRole.ADMIN, DeltaSystemRole.READ_ONLY_ADMIN)

    suspend fun enableUser(call: ApplicationCall) {
        val session = getSessionIfUserHasPermittedRole(allowedRoles, call)

        val user = findUserFromCallParameter(call)

        if (user.accountEnabled) {
            return call.respond(mapOf("message" to "Account already enabled"))
        }

        if (user.passwordLastSet == null) {
            if (user.isSSORequiredUser()) {
                logger.atInfo().addKeyValue("targetUserCN", user.cn)
                    .log("Setting random password and enabling SSO user")
                userService.setPasswordAndEnable(user.dn, randomBase64(18))
                auditService.userEnableAudit(user.cn, user.getUUID(), session.userCn, session.userGUID, call)
                return call.respond(mapOf("message" to "User ${user.cn} enabled"))
            } else {
                throw ApiError(
                    HttpStatusCode.BadRequest,
                    "cannot_enable_user_no_password",
                    "User '${user.cn}' pwdLastSet is null, will not enable",
                    "User '${user.cn}' does not have a password set and so cannot be enabled. Send them an activation email instead.",
                )
            }
        }

        logger.atInfo().addKeyValue("targetUserCN", user.cn).log("Enabling user")
        userService.enableAccountAndNotifications(user.dn)
        auditService.userEnableAudit(user.cn, user.getUUID(), session.userCn, session.userGUID, call)

        return call.respond(mapOf("message" to "User ${user.cn} enabled"))
    }


    suspend fun disableUser(call: ApplicationCall) {
        val session = getSessionIfUserHasPermittedRole(allowedRoles, call)

        val user = findUserFromCallParameter(call)

        if (!user.accountEnabled) {
            return call.respond(mapOf("message" to "Account already disabled"))
        }

        logger.atInfo().addKeyValue("targetUserCN", user.cn).log("Disabling user")
        userService.disableAccountAndNotifications(user.dn)
        auditService.userDisableAudit(user.cn, user.getUUID(), session.userCn, session.userGUID, call)
        // Clear any set password tokens so that they can't re-enable their account themselves
        setPasswordTokenService.clearTokenForUserCn(user.cn)

        return call.respond(mapOf("message" to "User ${user.cn} disabled"))
    }

    private suspend fun findUserFromCallParameter(call: ApplicationCall): LdapUser {
        val userCn = call.parameters.getOrFail("userCn")
        if (!VALID_USERNAME_REGEX.matches(userCn)) {
            throw ApiError(HttpStatusCode.BadRequest, "invalid_user_cn", "Invalid user cn $userCn")
        }

        return try {
            userLookupService.lookupUserByCn(userCn)
        } catch (e: NameNotFoundException) {
            throw ApiError(HttpStatusCode.NotFound, "user_not_found", "User not found")
        }
    }

    private fun LdapUser.isSSORequiredUser(): Boolean {
        return ssoConfig.ssoClients.any { it.required && email?.endsWith(it.emailDomain) == true }
    }
}
