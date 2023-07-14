package uk.gov.communities.delta.auth.security

import io.ktor.server.auth.*
import kotlinx.serialization.Serializable
import org.slf4j.LoggerFactory

@Serializable
data class DeltaLdapPrincipal(
    val cn: String,
    val memberOfGroupCNs: List<String>,
) : Principal

class LdapAuthenticationService(private val ldapService: ADLdapLoginService, private val requiredGroupCN: String) {

    private val logger = LoggerFactory.getLogger(LdapAuthenticationService::class.java)

    fun authenticate(credential: UserPasswordCredential): DeltaLdapPrincipal? {
        logger.debug("Authenticating LDAP service user '{}'", credential.name)

        when (val loginResult = ldapService.ldapLogin(credential.name, credential.password)) {
            is ADLdapLoginService.LdapLoginSuccess -> {
                val user = loginResult.user
                if (!user.memberOfCNs.contains(requiredGroupCN)) {
                    logger.atWarn().addKeyValue("username", credential.name)
                        .log("Authentication failed, user not member of required group {}", requiredGroupCN)
                    return null
                }

                logger.atInfo().addKeyValue("username", credential.name).log("LDAP authentication success")
                return DeltaLdapPrincipal(user.cn, user.memberOfCNs)
            }

            is ADLdapLoginService.LdapLoginFailure -> {
                logger.atInfo()
                    .addKeyValue("username", credential.name)
                    .addKeyValue("loginFailureType", loginResult.javaClass.simpleName)
                    .log("LDAP authentication failed")
                return null
            }
        }
    }
}
