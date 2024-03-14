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

class UserAuditService(private val userAuditTrailRepo: UserAuditTrailRepo, private val dbPool: DbPool) {
    suspend fun getAuditForUser(userCn: String) = getAudit(userCn, null)

    suspend fun getAuditForUserPaged(userCn: String, page: Int, pageSize: Int) =
        getAudit(userCn, Pair(pageSize, (page - 1) * pageSize))

    private suspend fun getAudit(userCn: String, limitOffset: Pair<Int, Int>?): List<UserAuditTrailRepo.UserAuditRow> {
        return withContext(Dispatchers.IO) {
            dbPool.useConnectionBlocking("user_audit_read") {
                userAuditTrailRepo.getAuditForUser(it, userCn, limitOffset)
            }
        }
    }

    suspend fun userSSOLoginAudit(
        userCn: String,
        ssoClient: AzureADSSOClient,
        azureUserObjectId: String,
        call: ApplicationCall,
    ) {
        insertAuditRow(
            UserAuditTrailRepo.AuditAction.SSO_LOGIN, userCn, null, call.callId!!,
            Json.encodeToString(
                SSOLoginAuditData(ssoClient.internalId, azureUserObjectId)
            )
        )
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

    // A user doing something to their own account with no extra data
    private fun insertAnonSimpleAuditRowFun(auditAction: UserAuditTrailRepo.AuditAction): suspend (String, ApplicationCall) -> Unit {
        return { userCn: String, call: ApplicationCall ->
            insertAuditRow(auditAction, userCn, null, call.callId!!, "{}")
        }
    }

    // A user altering changing someone else's account with no extra data
    private fun insertSimpleAuditRowFun(auditAction: UserAuditTrailRepo.AuditAction): suspend (String, String, ApplicationCall) -> Unit {
        return { userCn: String, editingUserCn: String, call: ApplicationCall ->
            insertAuditRow(auditAction, userCn, editingUserCn, call.callId!!, "{}")
        }
    }

    // A user doing something to their own account
    private fun insertAnonDetailedAuditRowFun(auditAction: UserAuditTrailRepo.AuditAction): suspend (String, ApplicationCall, String) -> Unit {
        return { userCn: String, call: ApplicationCall, encodedActionData: String ->
            insertAuditRow(auditAction, userCn, null, call.callId!!, encodedActionData)
        }
    }

    // A user altering changing someone else's account
    private fun insertDetailedAuditRowFun(auditAction: UserAuditTrailRepo.AuditAction): suspend (String, String, ApplicationCall, String) -> Unit {
        return { userCn: String, editingUserCn: String, call: ApplicationCall, encodedActionData: String ->
            insertAuditRow(auditAction, userCn, editingUserCn, call.callId!!, encodedActionData)
        }
    }

    private suspend fun insertAuditRow(
        action: UserAuditTrailRepo.AuditAction,
        userCn: String,
        editingUserCn: String?,
        requestId: String,
        encodedActionData: String,
    ) {
        withContext(Dispatchers.IO) {
            dbPool.useConnectionBlocking("Auditing $action") {
                userAuditTrailRepo.insertAuditRow(
                    it, action, userCn, editingUserCn, requestId, encodedActionData
                )
                it.commit()
            }
        }
    }

    @Serializable
    private data class SSOLoginAuditData(val ssoClientId: String, val azureUserObjectId: String)
}
