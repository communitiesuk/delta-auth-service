package uk.gov.communities.delta.auth.services

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import uk.gov.communities.delta.auth.config.LDAPConfig
import uk.gov.communities.delta.auth.plugins.monitoring.SpanFactory
import uk.gov.communities.delta.auth.repositories.LdapRepository
import javax.naming.ldap.InitialLdapContext
import kotlin.contracts.ExperimentalContracts
import kotlin.contracts.InvocationKind
import kotlin.contracts.contract

class LdapServiceUserBind(
    private val ldapConfig: LDAPConfig,
    private val ldapRepository: LdapRepository,
    private val ldapSpanFactory: SpanFactory,
) {
    @OptIn(ExperimentalContracts::class)
    suspend fun <R> useServiceUserBind(block: (InitialLdapContext) -> R): R {
        contract {
            callsInPlace(block, InvocationKind.AT_MOST_ONCE)
        }
        return withContext(Dispatchers.IO) {
            val span = ldapSpanFactory("AD-ldap-service-user").startSpan()
            val scope = span.makeCurrent()
            try {
                val ctx = ldapRepository.bind(
                    ldapConfig.authServiceUserDn,
                    ldapConfig.authServiceUserPassword,
                    poolConnection = true
                )
                try {
                    block(ctx)
                } finally {
                    ctx.close()
                }
            } finally {
                scope.close()
                span.end()
            }
        }
    }
}
