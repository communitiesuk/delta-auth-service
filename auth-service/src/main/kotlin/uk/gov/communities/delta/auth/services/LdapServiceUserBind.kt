package uk.gov.communities.delta.auth.services

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.jetbrains.annotations.Blocking
import uk.gov.communities.delta.auth.config.LDAPConfig
import uk.gov.communities.delta.auth.repositories.LdapRepository
import javax.naming.directory.Attributes
import javax.naming.directory.SearchControls
import javax.naming.ldap.Control
import javax.naming.ldap.InitialLdapContext
import javax.naming.ldap.PagedResultsControl
import javax.naming.ldap.PagedResultsResponseControl
import kotlin.contracts.ExperimentalContracts
import kotlin.contracts.InvocationKind
import kotlin.contracts.contract

class LdapServiceUserBind(
    private val ldapConfig: LDAPConfig,
    private val ldapRepository: LdapRepository,
) {
    @OptIn(ExperimentalContracts::class)
    suspend fun <R> useServiceUserBind(block: (InitialLdapContext) -> R): R {
        contract {
            callsInPlace(block, InvocationKind.AT_MOST_ONCE)
        }
        return withContext(Dispatchers.IO) {
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
        }
    }
}
