package uk.gov.communities.delta.auth.security

import io.ktor.server.auth.*
import io.ktor.server.auth.ldap.*
import kotlinx.serialization.Serializable
import org.slf4j.LoggerFactory
import uk.gov.communities.delta.auth.config.LDAPConfig
import javax.naming.Context
import javax.naming.directory.DirContext

@Serializable
data class DeltaLdapPrincipal(
    val cn: String,
    val memberOfGroupDNs: List<String>,
) : Principal {
    val memberOfGroupCNs = memberOfGroupDNs.mapNotNull {
        val match = DeltaADLdapAuthentication.groupCnRegex.matchEntire(it)
        match?.groups?.get(1)?.value
    }
}

class DeltaADLdapAuthentication {
    companion object {
        const val NAME = "delta-ldap-service-users-basic"
        val usernameRegex = Regex("^[\\w-.!]+$")
        val groupCnRegex = Regex(LDAPConfig.LDAP_GROUP_DN_FORMAT.replace("%s", "([\\w-]+)"))
    }

    private val logger = LoggerFactory.getLogger(DeltaADLdapAuthentication::class.java)

    fun authenticate(credential: UserPasswordCredential): DeltaLdapPrincipal? {
        if (!credential.name.matches(usernameRegex)) {
            logger.warn("Invalid username {}", credential.name)
            return null
        }

        logger.debug("Authenticating LDAP service user '{}'", credential.name)
        val principal = ldapAuthenticate(
            credential,
            LDAPConfig.LDAP_URL,
            { env ->
                env[Context.SECURITY_AUTHENTICATION] = "simple"
                env[Context.SECURITY_PRINCIPAL] = LDAPConfig.LDAP_SERVICE_USER_DN_FORMAT.format(credential.name)
                env[Context.SECURITY_CREDENTIALS] = credential.password
            }
        ) {
            val userDn = environment["java.naming.security.principal"] as String
            val memberOf = getMemberOfList(userDn)

            if (memberOf.contains(LDAPConfig.LDAP_GROUP_DN_FORMAT.format("dluhc-service-users"))) {
                logger.info("Authenticated user {}", it.name)
                DeltaLdapPrincipal(it.name, memberOf)
            } else {
                logger.warn(
                    "Authenticated user {}, but not member of dluhc-service-users", it.name
                )
                null
            }
        }
        if (principal == null) {
            logger.info("LDAP authentication failed for user '{}'", credential.name)
        }
        return principal
    }

    @Suppress("UNCHECKED_CAST")
    private fun DirContext.getMemberOfList(userDn: String): List<String> {
        return getAttributes(
            userDn, arrayOf("memberOf")
        ).get("memberOf").all.asSequence().toList() as List<String>
    }
}
