package uk.gov.communities.delta.auth.repositories

import kotlinx.serialization.Serializable
import kotlinx.serialization.Transient
import org.jetbrains.annotations.Blocking
import org.slf4j.LoggerFactory
import uk.gov.communities.delta.auth.config.DeltaConfig
import uk.gov.communities.delta.auth.config.LDAPConfig
import uk.gov.communities.delta.auth.plugins.NoUserException
import uk.gov.communities.delta.auth.utils.toActiveDirectoryGUIDSearchString
import uk.gov.communities.delta.auth.utils.toGUIDString
import java.lang.Integer.parseInt
import java.time.Instant
import java.util.*
import javax.naming.Context
import javax.naming.NamingException
import javax.naming.directory.Attribute
import javax.naming.directory.Attributes
import javax.naming.directory.InitialDirContext
import javax.naming.directory.SearchControls
import javax.naming.ldap.Control
import javax.naming.ldap.InitialLdapContext
import javax.naming.ldap.PagedResultsControl
import javax.naming.ldap.PagedResultsResponseControl
import kotlin.collections.set
import kotlin.time.Duration.Companion.seconds

class LdapRepository(
    private val ldapConfig: LDAPConfig,
    private val objectGUIDMode: ObjectGUIDMode,
    private val initialLdapContextFactory: ((Hashtable<String, String>) -> InitialLdapContext)? = null
) {
    enum class ObjectGUIDMode {
        OLD_MANGLED, NEW_JAVA_UUID_STRING;
    }

    private val logger = LoggerFactory.getLogger(javaClass)
    private val groupDnToCnRegex = Regex(ldapConfig.groupDnFormat.replace("%s", "([\\w-]+)"))
    private val datamartDeltaDataProviders = "datamart-delta-data-providers-"
    private val datamartDeltaDataCertifiers = "datamart-delta-data-certifiers"
    private val datamartDeltaStatsDataCertifiers = "datamart-delta-stats-data-certifiers-"

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

        if (objectGUIDMode == ObjectGUIDMode.NEW_JAVA_UUID_STRING) {
            env["java.naming.ldap.attributes.binary"] = "objectGUID imported-guid"
        }

        return try {
            val context = initialLdapContextFactory?.invoke(env) ?: InitialLdapContext(env, null)
            logger.debug("Successful bind for DN {}", userDn)
            context
        } catch (e: NamingException) {
            logger.debug("LDAP bind failed for user $userDn", e)
            throw e
        }
    }

    private val attributeNames = arrayOf(
        "cn",
        "distinguishedName",
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
        "st",
        "pwdLastSet",
    )

    private fun getUserFromAttributes(attributes: Attributes): LdapUser {
        val cn = attributes.get("cn")?.get() as String? ?: throw InvalidLdapUserException("No value for attribute cn")
        val dn = attributes.get("distinguishedName").get() as String?
            ?: throw InvalidLdapUserException("No value for attribute dn")
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
        val notificationStatus = attributes.get("st")?.get() as String?
        val passwordLastSet = attributes.getPwdLastSet()
        val memberOfGroupDNs = attributes.getMemberOfList()
        val accountEnabled = attributes.getAccountEnabled()
        val mangledDeltaObjectGuid = when (objectGUIDMode) {
            ObjectGUIDMode.OLD_MANGLED -> attributes.getMangledDeltaObjectGUID()
            ObjectGUIDMode.NEW_JAVA_UUID_STRING -> null
        }
        val javaUUIDObjectGuid = when (objectGUIDMode) {
            ObjectGUIDMode.OLD_MANGLED -> null
            ObjectGUIDMode.NEW_JAVA_UUID_STRING -> attributes.getNewModeObjectGuidString()
        }

        val memberOfGroupCNs = memberOfGroupDNs.mapNotNull {
            val match = groupDnToCnRegex.matchEntire(it)
            match?.groups?.get(1)?.value
        }
        return LdapUser(
            dn = dn,
            cn = cn,
            memberOfCNs = memberOfGroupCNs,
            email = email,
            deltaTOTPSecret = totpSecret,
            firstName = firstName,
            lastName = surname,
            fullName = fullName,
            accountEnabled = accountEnabled,
            mangledDeltaObjectGuid = mangledDeltaObjectGuid,
            javaUUIDObjectGuid = javaUUIDObjectGuid,
            telephone = telephone,
            mobile = mobile,
            positionInOrganisation = positionInOrganisation,
            reasonForAccess = reasonForAccess,
            comment = comment,
            notificationStatus = notificationStatus,
            passwordLastSet = passwordLastSet,
        )
    }

    @Blocking
    fun mapUserFromContext(ctx: InitialDirContext, userDn: String): LdapUser {
        val attributes = ctx.getAttributes(userDn, attributeNames)
        return getUserFromAttributes(attributes)
    }

    private val searchDn = ldapConfig.deltaUserDnFormat.removePrefix("CN=%s,")
    private fun searchControls(): SearchControls {
        val searchControls = SearchControls()
        searchControls.searchScope = SearchControls.ONELEVEL_SCOPE
        searchControls.timeLimit = 30.seconds.inWholeMilliseconds.toInt()
        searchControls.returningAttributes = attributeNames
        return searchControls
    }

    @Blocking
    fun mapUserFromContext(ctx: InitialDirContext, userGUID: UUID): LdapUser {
        val adGUIDString = userGUID.toActiveDirectoryGUIDSearchString()
        val filter = "(objectGUID=$adGUIDString)"
        val searchResults = ctx.search(searchDn, filter, searchControls())
        val attributes = if (searchResults.hasMore()) {
            searchResults.next().attributes
        } else {
            logger.atError().log("Couldn't find user with GUID $userGUID")
            throw NoUserException("Couldn't find user with GUID $userGUID")
        }
        return if (searchResults.hasMore()) {
            logger.atError().log("Multiple users found with GUID $userGUID")
            throw Exception("Multiple users found on GUID lookup")
        } else {
            getUserFromAttributes(attributes)
        }
    }

    private fun Attributes.getMemberOfList(): List<String> {
        return get("memberOf")?.asList()?:emptyList()
    }

    @Suppress("UNCHECKED_CAST")
    private fun Attribute.asList(): List<String> {
        return all.asSequence().toList() as List<String>
    }

    private fun Attributes.getAccountEnabled(): Boolean {
        val userAccountControlDecimal = get("userAccountControl")?.get() as String
        val userAccountControl = parseInt(userAccountControlDecimal)
        // https://learn.microsoft.com/en-us/troubleshoot/windows-server/identity/useraccountcontrol-manipulate-account-properties
        return userAccountControl and (1 shl 1) == 0
    }

    private fun Attributes.getPwdLastSet(): Instant? {
        val pwdLastSet = (get("pwdLastSet")?.get() as String?) ?: return null
        if (pwdLastSet == "0") return null
        return win32FileTimeToInstant(pwdLastSet.toLong())
    }

    private fun win32FileTimeToInstant(fileTime: Long): Instant {
        return Instant.ofEpochMilli(fileTime / 10000 - 11644473600000L)
    }

    fun getUsersForOrgAccessGroupWithRoles(accessGroupName: String, organisationId: String): List<UserWithRoles> {
        val formattedAccessGroupName = "${LDAPConfig.DATAMART_DELTA_PREFIX}$accessGroupName-$organisationId"

        val ctx = bind(ldapConfig.authServiceUserDn, ldapConfig.authServiceUserPassword)
        try {
            val searchControls = SearchControls().apply {
                searchScope = SearchControls.SUBTREE_SCOPE
                returningAttributes = attributeNames
            }

            val results = ctx.search(
                ldapConfig.userContainerDn,
                "(&(objectClass=user)(memberOf=cn=$formattedAccessGroupName,${ldapConfig.groupContainerDn}))",
                searchControls
            )

            val usersWithRoles = mutableListOf<UserWithRoles>()

            while (results.hasMore()) {
                val userAttrs = results.next().attributes
                val user = getUserFromAttributes(userAttrs)

                if (user.memberOfCNs.contains("datamart-delta-user-dclg") || !user.accountEnabled) {
                    continue
                }

                usersWithRoles.add(createUserWithRoles(user, organisationId))
            }

            logger.info("Retrieved ${usersWithRoles.size} users with their roles for organisation '$organisationId' and access group '$accessGroupName'")
            return usersWithRoles
        } finally {
            ctx.close()
        }
    }

    private fun createUserWithRoles(user: LdapUser, organisationId: String): UserWithRoles {
        val allGroups = user.memberOfCNs
        val userRoles = allGroups.mapNotNull { role ->
            when {
                role.equals("${datamartDeltaDataProviders}$organisationId", ignoreCase = true) -> "Data provider"
                role.equals(datamartDeltaDataCertifiers, ignoreCase = true) -> "Data certifier"
                role.equals("${datamartDeltaStatsDataCertifiers}$organisationId", ignoreCase = true) -> "Data certifier (stats collections)"
                else -> null
            }
        }.distinct()

        return UserWithRoles(
            cn = user.cn,
            objectGUID = user.getGUID().toString(),
            mail = user.email ?: "",
            fullName = user.fullName,
            roles = userRoles
        )
    }

    @Serializable
    data class UserWithRoles(
        val cn: String,
        val objectGUID: String,
        val mail: String,
        val fullName: String,
        val roles: List<String>
    )
}

// These attributes should be treated as binary i.e.
// env["java.naming.ldap.attributes.binary"] = "objectGUID imported-guid"
// but Delta historically Delta didn't do that and instead attempts to use them as strings, which discards much of the value.
// This service supports either the mangled ids or the "new" mode, which just means correctly interpreting Active Directory's objectGUID
@OptIn(ExperimentalStdlibApi::class)
fun Attributes.getMangledDeltaObjectGUID(): String {
    val importedGuid = get("imported-guid")?.get() as String?
    val guidStringToUse = importedGuid ?: (get("objectGUID").get() as String)

    return guidStringToUse.toByteArray().toHexString().trimStart { it == '0' }
}

fun Attributes.getNewModeObjectGuidString(): String {
    val objectGuid = get("objectGUID").get() as ByteArray
    return objectGuid.toGUIDString()
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
    // Exactly one of these should be populated
    val mangledDeltaObjectGuid: String?,
    // Text representation of the user's objectGUID
    val javaUUIDObjectGuid: String?,
    val telephone: String?,
    val mobile: String?,
    val positionInOrganisation: String?,
    val reasonForAccess: String?,
    val comment: String?,
    val notificationStatus: String?,
    // Not required by Delta, but used internally
    @Transient val passwordLastSet: Instant? = null,
) {
    fun getGUID(): UUID {
        return UUID.fromString(javaUUIDObjectGuid)
    }
}

fun LdapUser.isInternal() : Boolean {
    return this.memberOfCNs.contains(DeltaConfig.DATAMART_DELTA_INTERNAL_USER)
}

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

        while (searchResult.hasMore()) {
            searchResult.next().attributes.let(mapper)?.let { accumulatedResults.add(it) }
        }

        pagedResultsCookie = responseControls?.filterIsInstance<PagedResultsResponseControl>()
            ?.firstOrNull()?.cookie
        requestControls = arrayOf(PagedResultsControl(pageSize, pagedResultsCookie, Control.CRITICAL))
    } while (pagedResultsCookie != null)

    return accumulatedResults
}
