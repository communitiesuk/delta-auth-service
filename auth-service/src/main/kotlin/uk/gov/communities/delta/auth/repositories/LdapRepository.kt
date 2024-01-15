package uk.gov.communities.delta.auth.repositories

import kotlinx.serialization.Serializable
import org.jetbrains.annotations.Blocking
import org.slf4j.LoggerFactory
import uk.gov.communities.delta.auth.config.LDAPConfig
import java.lang.Integer.parseInt
import java.util.*
import javax.naming.Context
import javax.naming.NamingException
import javax.naming.directory.Attributes
import javax.naming.directory.InitialDirContext
import javax.naming.directory.SearchControls
import javax.naming.ldap.Control
import javax.naming.ldap.InitialLdapContext
import javax.naming.ldap.PagedResultsControl
import javax.naming.ldap.PagedResultsResponseControl
import kotlin.text.HexFormat

class LdapRepository(
    private val ldapConfig: LDAPConfig,
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

    @Blocking
    fun mapUserFromContext(ctx: InitialDirContext, userDn: String): LdapUser {
        val attributes =
            ctx.getAttributes(
                userDn,
                arrayOf(
                    "cn",
                    "memberOf",
                    "mail",
                    "unixHomeDirectory", // Delta TOTP secret
                    "givenName",
                    "sn",
                    "userAccountControl",
                    "objectGUID",
                    "imported-guid",
                    "telephoneNumber",
                    "mobile",
                    "title", // Delta "Position in organisation"
                    "description", // Delta "Reason for access"
                    "comment",
                )
            )

        val cn = attributes.get("cn")?.get() as String? ?: throw InvalidLdapUserException("No value for attribute cn")
        val email = attributes.get("mail")?.get() as String?
        val totpSecret = attributes.get("unixHomeDirectory")?.get() as String?
        val firstName = attributes.get("givenName")?.get() as String? ?: ""
        val surname = attributes.get("sn")?.get() as String? ?: ""
        val fullName = "$firstName $surname"
        val telephone = attributes.get("telephoneNumber")?.get() as String?
        val mobile = attributes.get("mobile")?.get() as String?
        val positionInOrganisation = attributes.get("title")?.get() as String?
        val reasonForAccess = attributes.get("description")?.get() as String?
        val comment = attributes.get("comment")?.get() as String?
        val memberOfGroupDNs = attributes.getMemberOfList()
        val accountEnabled = attributes.getAccountEnabled()
        val deltaGuid = attributes.getMangledDeltaObjectGUID()

        val memberOfGroupCNs = memberOfGroupDNs.mapNotNull {
            val match = groupDnToCnRegex.matchEntire(it)
            match?.groups?.get(1)?.value
        }
        return LdapUser(
            dn = userDn,
            cn = cn,
            memberOfCNs = memberOfGroupCNs,
            email = email,
            deltaTOTPSecret = totpSecret,
            firstName = firstName,
            lastName = surname,
            fullName = fullName,
            accountEnabled = accountEnabled,
            mangledDeltaObjectGuid = deltaGuid,
            telephone = telephone,
            mobile = mobile,
            positionInOrganisation = positionInOrganisation,
            reasonForAccess = reasonForAccess,
            comment = comment,
        )
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

    @OptIn(ExperimentalStdlibApi::class)
    private fun Attributes.getMangledDeltaObjectGUID(): String {
        // These attributes should be treated as binary i.e.
        // env.["java.naming.ldap.attributes.binary"] = "objectGUID imported-guid"
        // but Delta doesn't do that and instead attempts to use them as strings, which discards much of the value.
        // These ids are scattered through the Delta database now though, so we keep them for compatibility
        val importedGuid = get("imported-guid")?.get() as String?
        val guidStringToUse = importedGuid ?: (get("objectGUID").get() as String)

        return guidStringToUse.toByteArray().toHexString().trimStart { it == '0' }
    }
}

@Serializable
data class LdapUser(
    val dn: String,
    val cn: String,
    val memberOfCNs: List<String>,
    val email: String?,
    val deltaTOTPSecret: String?,
    val firstName: String,
    val lastName: String,
    val fullName: String,
    val accountEnabled: Boolean,
    val mangledDeltaObjectGuid: String,
    val telephone: String?,
    val mobile: String?,
    val positionInOrganisation: String?,
    val reasonForAccess: String?,
    val comment: String?,
)

class InvalidLdapUserException(message: String) : Exception(message)

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
