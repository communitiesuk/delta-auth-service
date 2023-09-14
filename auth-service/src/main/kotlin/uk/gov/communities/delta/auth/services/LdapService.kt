package uk.gov.communities.delta.auth.services

import io.ktor.util.reflect.*
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.Serializable
import org.jetbrains.annotations.Blocking
import org.slf4j.LoggerFactory
import uk.gov.communities.delta.auth.config.LDAPConfig
import java.lang.Integer.parseInt
import java.util.*
import javax.naming.Context
import javax.naming.NamingException
import javax.naming.directory.*
import javax.naming.ldap.InitialLdapContext
import kotlin.contracts.ExperimentalContracts
import kotlin.contracts.InvocationKind
import kotlin.contracts.contract

class LdapService(
    private val ldapConfig: LDAPConfig
) {

    private val logger = LoggerFactory.getLogger(javaClass)
    private val groupDnToCnRegex = Regex(ldapConfig.groupDnFormat.replace("%s", "([\\w-]+)"))

    @Blocking
    fun bind(userDn: String, password: String, poolConnection: Boolean = false): InitialLdapContext {
        val env = Hashtable<String, String>()
        env[Context.INITIAL_CONTEXT_FACTORY] = "com.sun.jndi.ldap.LdapCtxFactory"
        env[Context.PROVIDER_URL] = ldapConfig.deltaLdapUrl
        env[Context.SECURITY_AUTHENTICATION] = "simple"
        env[Context.SECURITY_PRINCIPAL] = userDn
        env[Context.SECURITY_CREDENTIALS] = password
        env["com.sun.jndi.ldap.connect.timeout"] = "5000"
        env["com.sun.jndi.ldap.read.timeout"] = "10000"
        env["com.sun.jndi.ldap.connect.pool"] = if (poolConnection) "true" else "false"
        env["com.sun.jndi.ldap.connect.pool.protocol"] = "plain ssl"
        env["com.sun.jndi.ldap.connect.pool.timeout"] =
            "60000" // Milliseconds. Relevant timeouts are 900s for AD and 350s for NLB.

        return try {
            val context = InitialLdapContext(env, null)
            logger.debug("Successful bind for DN {}", userDn)
            context
        } catch (e: NamingException) {
            logger.debug("LDAP bind failed for user $userDn", e)
            throw e
        }
    }

    @OptIn(ExperimentalContracts::class)
    suspend fun <R> useServiceUserBind(block: (InitialLdapContext) -> R): R {
        contract {
            callsInPlace(block, InvocationKind.AT_MOST_ONCE)
        }
        return withContext(Dispatchers.IO) {
            val ctx = bind(ldapConfig.authServiceUserDn, ldapConfig.authServiceUserPassword, poolConnection = true)
            try {
                block(ctx)
            } finally {
                ctx.close()
            }
        }
    }

    @Blocking
    fun mapUserFromContext(ctx: InitialDirContext, userDn: String): LdapUser {
        val attributes =
            ctx.getAttributes(
                userDn,
                arrayOf("cn", "memberOf", "mail", "unixHomeDirectory", "givenName", "sn", "userAccountControl")
            )

        val cn = attributes.get("cn")?.get() as String? ?: throw InvalidLdapUserException("No value for attribute cn")
        val email = attributes.get("mail")?.get() as String?
        val totpSecret = attributes.get("unixHomeDirectory")?.get() as String?
        val firstName = attributes.get("givenName")?.get() as String?
        val surname = attributes.get("sn")?.get() as String?
        val name = (firstName ?: "") + " " + (surname ?: "")
        val memberOfGroupDNs = attributes.getMemberOfList()
        val accountEnabled = attributes.getAccountEnabled()

        val memberOfGroupCNs = memberOfGroupDNs.mapNotNull {
            val match = groupDnToCnRegex.matchEntire(it)
            match?.groups?.get(1)?.value
        }
        return LdapUser(userDn, cn, memberOfGroupCNs, email, totpSecret, name, accountEnabled)
    }

    @Suppress("UNCHECKED_CAST")
    private fun Attributes.getMemberOfList(): List<String> {
        return get("memberOf").all.asSequence().toList() as List<String>
    }

    private fun Attributes.getAccountEnabled(): Boolean {
        val userAccountControlDecimal = get("userAccountControl")?.get() as String
        val userAccountControl = parseInt(userAccountControlDecimal)
        // https://learn.microsoft.com/en-us/troubleshoot/windows-server/identity/useraccountcontrol-manipulate-account-properties
        return userAccountControl and (1 shl 1) == 0
    }
}

@Serializable
data class LdapUser(
    val dn: String,
    val cn: String,
    val memberOfCNs: List<String>,
    val email: String?,
    val deltaTOTPSecret: String?,
    val name: String,
    val accountEnabled: Boolean,
)

class InvalidLdapUserException(message: String) : Exception(message)
