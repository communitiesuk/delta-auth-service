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
    suspend fun getAuditForUser(userCn: String): List<UserAuditTrailRepo.UserAuditRow> {
        return withContext(Dispatchers.IO) {
            dbPool.useConnectionBlocking("user_audit_read") {
                userAuditTrailRepo.getAuditForUser(it, userCn)
            }
        }
    }

    val userFormLoginAudit = insertSimpleAuditRowFun(UserAuditTrailRepo.AuditAction.FORM_LOGIN)

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

    val userForgotPasswordAudit = insertSimpleAuditRowFun(UserAuditTrailRepo.AuditAction.FORGOT_PASSWORD_EMAIL)

    val setPasswordEmailAudit = insertSimpleAuditRowFun(UserAuditTrailRepo.AuditAction.SET_PASSWORD_EMAIL)

    val resetPasswordAudit = insertSimpleAuditRowFun(UserAuditTrailRepo.AuditAction.RESET_PASSWORD)

    val setPasswordAudit = insertSimpleAuditRowFun(UserAuditTrailRepo.AuditAction.SET_PASSWORD)

    val userSelfRegisterAudit = insertSimpleAuditRowFun(UserAuditTrailRepo.AuditAction.SELF_REGISTER)

    suspend fun ssoUserCreatedAudit(userCn: String, azureUserObjectId: String, ssoClient: AzureADSSOClient, call: ApplicationCall) {
        insertAuditRow(
            UserAuditTrailRepo.AuditAction.SSO_USER_CREATED, userCn, null, call.callId!!,
            Json.encodeToString(SSOLoginAuditData(ssoClient.internalId, azureUserObjectId))
        )
    }

    private fun insertSimpleAuditRowFun(auditAction: UserAuditTrailRepo.AuditAction): suspend (String, ApplicationCall) -> Unit {
        return { userCn: String, call: ApplicationCall ->
            insertAuditRow(auditAction, userCn, null, call.callId!!, "{}")
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
            dbPool.useConnectionBlocking("audit_sso_login") {
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
