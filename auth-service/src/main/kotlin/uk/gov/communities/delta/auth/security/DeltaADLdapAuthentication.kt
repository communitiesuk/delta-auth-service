package uk.gov.communities.delta.auth.security

import io.ktor.server.auth.*
import io.ktor.server.auth.ldap.*
import org.slf4j.LoggerFactory
import uk.gov.communities.delta.auth.Config
import javax.naming.Context
import javax.naming.directory.DirContext


data class DeltaLdapPrincipal(
    val cn: String,
    val groups: List<String>,
) : Principal

class DeltaADLdapAuthentication {
    companion object {
        const val NAME = "delta-ldap-service-users-basic"
        val usernameRegex = Regex("^[\\w-.!]+$")
    }

    private val logger = LoggerFactory.getLogger(DeltaADLdapAuthentication::class.java)

    fun authenticate(credential: UserPasswordCredential): DeltaLdapPrincipal? {
        if (!credential.name.matches(usernameRegex)) {
            logger.warn("Invalid username {}", credential.name)
            return null
        }

        return ldapAuthenticate(
            credential,
            Config.LDAP_URL,
            { env ->
                env[Context.SECURITY_AUTHENTICATION] = "simple"
                env[Context.SECURITY_PRINCIPAL] = Config.LDAP_SERVICE_USER_DN_FORMAT.format(credential.name)
                env[Context.SECURITY_CREDENTIALS] = credential.password
            }
        ) {
            val userDn = environment["java.naming.security.principal"] as String
            val memberOf = getMemberOfList(userDn)

            if (memberOf.contains(Config.LDAP_GROUP_DN_FORMAT.format("dluhc-service-users"))) {
                logger.info("Authenticated user {}", it.name)
                DeltaLdapPrincipal(it.name, memberOf)
            } else {
                logger.warn(
                    "Authenticated user {}, but not member of dluhc-service-users", it.name
                )
                null
            }
        }
    }

    @Suppress("UNCHECKED_CAST")
    private fun DirContext.getMemberOfList(userDn: String): List<String> {
        return getAttributes(
            userDn, arrayOf("memberOf")
        ).get("memberOf").all.asSequence().toList() as List<String>
    }
}
