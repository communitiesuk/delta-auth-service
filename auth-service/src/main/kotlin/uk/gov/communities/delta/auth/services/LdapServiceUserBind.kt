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

@Blocking
fun <T> InitialLdapContext.searchPaged(
    dn: String, filter: String, searchControls: SearchControls,
    pageSize: Int, mapper: (Attributes) -> T?,
): List<T> {
    val accumulatedResults = mutableListOf<T>()
    var pagedResultsCookie: ByteArray?
    requestControls = arrayOf(
        PagedResultsControl(pageSize, Control.CRITICAL)
    )

    do {
        val searchResult = search(dn, filter, searchControls)

        do {
            searchResult.next().attributes.let(mapper)?.let { accumulatedResults.add(it) }
        } while (searchResult.hasMore())

        pagedResultsCookie = responseControls?.filterIsInstance(PagedResultsResponseControl::class.java)
            ?.firstOrNull()?.cookie
        requestControls = arrayOf(PagedResultsControl(pageSize, pagedResultsCookie, Control.CRITICAL))
    } while (pagedResultsCookie != null)

    return accumulatedResults
}
