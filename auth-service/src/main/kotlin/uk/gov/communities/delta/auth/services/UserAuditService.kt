package uk.gov.communities.delta.auth.services

import io.ktor.server.application.*
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

class UserAuditService(private val userAuditTrailRepo: UserAuditTrailRepo, private val dbPool: DbPool) {
    suspend fun userFormLoginAudit(userCn: String, call: ApplicationCall) {
        withContext(Dispatchers.IO) {
            dbPool.useConnectionBlocking("audit_form_login") {
                userAuditTrailRepo.userFormLoginAudit(it, userCn, call)
                it.commit()
            }
        }
    }
}
