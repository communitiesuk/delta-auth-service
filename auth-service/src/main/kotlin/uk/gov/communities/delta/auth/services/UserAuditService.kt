package uk.gov.communities.delta.auth.services

import io.ktor.server.application.*
import io.ktor.server.plugins.callid.*
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import uk.gov.communities.delta.auth.config.AzureADSSOClient
import uk.gov.communities.delta.auth.repositories.DbPool
import uk.gov.communities.delta.auth.repositories.UserAuditTrailRepo
import java.time.Instant
import java.util.*

class UserAuditService(private val userAuditTrailRepo: UserAuditTrailRepo, private val dbPool: DbPool) {
    suspend fun getAuditForUser(userGUID: UUID) = withContext(Dispatchers.IO) {
        dbPool.useConnectionBlocking("user_audit_read") {
            userAuditTrailRepo.getAuditForUser(it, userGUID, null)
        }
    }


    suspend fun getAuditForUserPaged(
        userGUID: UUID,
        page: Int,
        pageSize: Int
    ): Pair<List<UserAuditTrailRepo.UserAuditRow>, Int> {
        val limitOffset = Pair(pageSize, (page - 1) * pageSize)
        return withContext(Dispatchers.IO) {
            dbPool.useConnectionBlocking("user_audit_read") {
                userAuditTrailRepo.getAuditForUser(it, userGUID, limitOffset)
                Pair(
                    userAuditTrailRepo.getAuditForUser(it, userGUID, limitOffset),
                    userAuditTrailRepo.getAuditItemCount(it, userGUID),
                )
            }
        }
    }

    suspend fun getAuditForAllUsers(from: Instant, to: Instant) = withContext(Dispatchers.IO) {
        dbPool.useConnectionBlocking("all_users_audit_read") {
            userAuditTrailRepo.getAuditForAllUsers(it, from, to)
        }
    }

    suspend fun userSSOLoginAudit(
        userGUID: UUID,
        ssoClient: AzureADSSOClient,
        azureUserObjectId: String,
        call: ApplicationCall,
    ) {
        insertAuditRow(
            UserAuditTrailRepo.AuditAction.SSO_LOGIN, userGUID, null, call.callId!!,
            Json.encodeToString(
                SSOLoginAuditData(ssoClient.internalId, azureUserObjectId)
            )
        )
    }


    suspend fun insertImpersonatingUserAuditRow(
        session: OAuthSession, impersonatedUserGUID: UUID, requestId: String
    ) {
        insertAuditRow(
            UserAuditTrailRepo.AuditAction.IMPERSONATE_USER,
            session.userGUID,
            null,
            requestId,
            Json.encodeToString(
                ImpersonateUserAuditData(impersonatedUserGUID.toString())
            )
        )
    }

    suspend fun checkIsNewUser(userGUID: UUID): Boolean {
        return withContext(Dispatchers.IO) {
            dbPool.useConnectionBlocking("check_is_new_user") {
                userAuditTrailRepo.checkIsNewUser(it,userGUID)
            }
        }
    }

    val userFormLoginAudit = insertAnonSimpleAuditRowFun(UserAuditTrailRepo.AuditAction.FORM_LOGIN)
    val resetPasswordEmailAudit = insertAnonSimpleAuditRowFun(UserAuditTrailRepo.AuditAction.RESET_PASSWORD_EMAIL)
    val adminResetPasswordEmailAudit = insertSimpleAuditRowFun(UserAuditTrailRepo.AuditAction.RESET_PASSWORD_EMAIL)
    val setPasswordEmailAudit = insertAnonSimpleAuditRowFun(UserAuditTrailRepo.AuditAction.SET_PASSWORD_EMAIL)
    val adminSetPasswordEmailAudit = insertSimpleAuditRowFun(UserAuditTrailRepo.AuditAction.SET_PASSWORD_EMAIL)
    val resetPasswordAudit = insertAnonSimpleAuditRowFun(UserAuditTrailRepo.AuditAction.RESET_PASSWORD)
    val setPasswordAudit = insertAnonSimpleAuditRowFun(UserAuditTrailRepo.AuditAction.SET_PASSWORD)
    val userSelfRegisterAudit =
        insertAnonDetailedAuditRowFun(UserAuditTrailRepo.AuditAction.USER_CREATED_BY_SELF_REGISTER)
    val userCreatedByAdminAudit = insertDetailedAuditRowFun(UserAuditTrailRepo.AuditAction.USER_CREATED_BY_ADMIN)
    val userCreatedBySSOAudit = insertAnonDetailedAuditRowFun(UserAuditTrailRepo.AuditAction.USER_CREATED_BY_SSO)
    val ssoUserCreatedByAdminAudit = insertDetailedAuditRowFun(UserAuditTrailRepo.AuditAction.SSO_USER_CREATED_BY_ADMIN)
    val userUpdateByAdminAudit = insertDetailedAuditRowFun(UserAuditTrailRepo.AuditAction.USER_UPDATE)
    val userUpdateAudit = insertAnonDetailedAuditRowFun(UserAuditTrailRepo.AuditAction.USER_UPDATE)
    val userEnableAudit = insertSimpleAuditRowFun(UserAuditTrailRepo.AuditAction.USER_ENABLE_BY_ADMIN)
    val userDisableAudit = insertSimpleAuditRowFun(UserAuditTrailRepo.AuditAction.USER_DISABLE_BY_ADMIN)
    val apiTokenCreationAudit = insertAnonSimpleAuditRowFun(UserAuditTrailRepo.AuditAction.API_TOKEN_CREATE)

    // A user doing something to their own account with no extra data
    private fun insertAnonSimpleAuditRowFun(auditAction: UserAuditTrailRepo.AuditAction): suspend (UUID, ApplicationCall) -> Unit {
        return { userGUID: UUID, call: ApplicationCall ->
            insertAuditRow(auditAction, userGUID, null, call.callId!!, "{}")
        }
    }

    // A user altering changing someone else's account with no extra data
    private fun insertSimpleAuditRowFun(auditAction: UserAuditTrailRepo.AuditAction): suspend (UUID, UUID, ApplicationCall) -> Unit {
        return { userGUID: UUID, editingUserGUID: UUID, call: ApplicationCall ->
            insertAuditRow(auditAction, userGUID, editingUserGUID, call.callId!!, "{}")
        }
    }

    // A user doing something to their own account
    private fun insertAnonDetailedAuditRowFun(auditAction: UserAuditTrailRepo.AuditAction): suspend (UUID, ApplicationCall, String) -> Unit {
        return { userGUID: UUID, call: ApplicationCall, encodedActionData: String ->
            insertAuditRow(auditAction, userGUID, null, call.callId!!, encodedActionData)
        }
    }

    // A user altering changing someone else's account
    private fun insertDetailedAuditRowFun(auditAction: UserAuditTrailRepo.AuditAction): suspend (UUID, UUID, ApplicationCall, String) -> Unit {
        return { userGUID: UUID, editingUserGUID: UUID, call: ApplicationCall, encodedActionData: String ->
            insertAuditRow(
                auditAction, userGUID, editingUserGUID, call.callId!!, encodedActionData
            )
        }
    }

    private suspend fun insertAuditRow(
        action: UserAuditTrailRepo.AuditAction,
        userGUID: UUID,
        editingUserGUID: UUID?,
        requestId: String,
        encodedActionData: String,
    ) {
        withContext(Dispatchers.IO) {
            dbPool.useConnectionBlocking("Auditing $action") {
                userAuditTrailRepo.insertAuditRow(
                    it, action, userGUID, editingUserGUID, requestId, encodedActionData
                )
                it.commit()
            }
        }
    }

    @Serializable
    private data class SSOLoginAuditData(val ssoClientId: String, val azureUserObjectId: String)

    @Serializable
    private data class ImpersonateUserAuditData(val impersonatedUserGUIDString: String)
}
