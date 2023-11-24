package uk.gov.communities.delta.auth.security

import io.ktor.server.auth.*
import kotlinx.serialization.Serializable
import org.slf4j.LoggerFactory
import uk.gov.communities.delta.auth.repositories.LdapUser

@Serializable
data class DeltaLdapPrincipal(
    val ldapUser: LdapUser,
) : Principal {
    val username = ldapUser.cn
}

class LdapAuthenticationService(private val ldapService: IADLdapLoginService, private val requiredGroupCN: String) {

    private val logger = LoggerFactory.getLogger(LdapAuthenticationService::class.java)

    suspend fun authenticate(credential: UserPasswordCredential): DeltaLdapPrincipal? {
        logger.debug("Authenticating LDAP service user '{}'", credential.name)

        when (val loginResult = ldapService.ldapLogin(credential.name, credential.password)) {
            is IADLdapLoginService.LdapLoginSuccess -> {
                val user = loginResult.user
                if (!user.memberOfCNs.contains(requiredGroupCN)) {
                    logger.atWarn().addKeyValue("username", credential.name)
                        .log("Authentication failed, user not member of required group {}", requiredGroupCN)
                    return null
                }

                logger.atInfo().addKeyValue("username", credential.name).log("LDAP authentication success")
                return DeltaLdapPrincipal(user)
            }

            is IADLdapLoginService.LdapLoginFailure -> {
                logger.atInfo()
                    .addKeyValue("username", credential.name)
                    .addKeyValue("loginFailureType", loginResult.javaClass.simpleName)
                    .log("LDAP authentication failed")
                return null
            }
        }
    }
}
