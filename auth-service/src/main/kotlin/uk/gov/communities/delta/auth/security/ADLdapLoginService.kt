package uk.gov.communities.delta.auth.security

import org.slf4j.LoggerFactory
import java.util.*
import javax.naming.AuthenticationException
import javax.naming.CommunicationException
import javax.naming.Context
import javax.naming.NamingException
import javax.naming.directory.Attributes
import javax.naming.directory.InitialDirContext

data class LdapUser(val cn: String, val memberOfCNs: List<String>)

interface ADLdapLoginService {
    fun ldapLogin(username: String, password: String): LdapLoginResult


    sealed interface LdapLoginResult
    class LdapLoginSuccess(val user: LdapUser) : LdapLoginResult
    sealed class LdapLoginFailure() : LdapLoginResult

    object BadConnection : LdapLoginFailure()
    object UnknownNamingException : LdapLoginFailure()

    object UnknownAuthenticationFailure : LdapLoginFailure()
    object InvalidUsername : LdapLoginFailure()

    sealed class ActiveDirectoryBindError(val code: String) : LdapLoginFailure()

    object DisabledAccount : ActiveDirectoryBindError("533")
    object AccountLocked : ActiveDirectoryBindError("775")
    object ExpiredPassword : ActiveDirectoryBindError("532")
    object PasswordNeedsReset : ActiveDirectoryBindError("773")
    object InvalidUsernameOrPassword : ActiveDirectoryBindError("52e")
    object UnknownAdSubErrorCode : ActiveDirectoryBindError("UNKNOWN")
}

class ADLdapLoginServiceImpl(private val config: Configuration) : ADLdapLoginService {

    data class Configuration(val ldapUrl: String, val userDnFormat: String, val groupDnFormat: String)

    private val logger = LoggerFactory.getLogger(this.javaClass)
    private val groupCnRegex = Regex(config.groupDnFormat.replace("%s", "([\\w-]+)"))

    override fun ldapLogin(username: String, password: String): ADLdapLoginService.LdapLoginResult {
        if (!username.matches(VALID_USERNAME_REGEX)) {
            logger.warn("Invalid username '{}'", username)
            return ADLdapLoginService.InvalidUsername
        }

        val userDn = config.userDnFormat.format(username)

        return ldapBind(userDn, password)
    }

    private fun ldapBind(userDn: String, password: String): ADLdapLoginService.LdapLoginResult {
        val env = Hashtable<String, Any?>()
        env[Context.INITIAL_CONTEXT_FACTORY] = "com.sun.jndi.ldap.LdapCtxFactory"
        env[Context.PROVIDER_URL] = config.ldapUrl
        env[Context.SECURITY_AUTHENTICATION] = "simple"
        env[Context.SECURITY_PRINCIPAL] = userDn
        env[Context.SECURITY_CREDENTIALS] = password

        return try {
            val context = InitialDirContext(env)
            logger.debug("Successful bind for DN {}", userDn)
            val user = mapContextToUser(context)
            context.close()
            ADLdapLoginService.LdapLoginSuccess(user)
        } catch (e: NamingException) {
            logger.debug("LDAP login failed for user $userDn", e)
            handleLdapException(e)
        }
    }

    private fun mapContextToUser(ctx: InitialDirContext): LdapUser {
        val userDn = ctx.environment[Context.SECURITY_PRINCIPAL] as String
        val attributes = ctx.getAttributes(userDn, arrayOf("cn", "memberOf"))

        val cn = attributes.get("cn").get() as String
        val memberOfGroupDNs = attributes.getMemberOfList()

        val memberOfGroupCNs = memberOfGroupDNs.mapNotNull {
            val match = groupCnRegex.matchEntire(it)
            match?.groups?.get(1)?.value
        }
        return LdapUser(cn, memberOfGroupCNs)
    }

    @Suppress("UNCHECKED_CAST")
    private fun Attributes.getMemberOfList(): List<String> {
        return get("memberOf").all.asSequence().toList() as List<String>
    }

    private fun handleLdapException(e: NamingException): ADLdapLoginService.LdapLoginFailure {
        when (e) {
            is AuthenticationException -> {
                val subErrorCodeMatch = ACTIVE_DIRECTORY_SUB_ERROR_CODE_ERROR_MESSAGE_REGEX.find(e.message!!)
                if (subErrorCodeMatch != null) {
                    val subErrorCode = subErrorCodeMatch.groupValues[1]
                    return activeDirectoryErrorCodes.getOrElse(subErrorCode) {
                        logger.warn("Unknown AD sub error code $subErrorCode", e)
                        ADLdapLoginService.UnknownAdSubErrorCode
                    }
                }
                logger.warn("Authentication failure, no AD sub error code found", e)
                return ADLdapLoginService.UnknownAuthenticationFailure
            }

            is CommunicationException -> {
                logger.error("Failed to connect to LDAP server", e)
                return ADLdapLoginService.BadConnection
            }

            else -> {
                logger.warn("Unknown authentication failure", e)
                return ADLdapLoginService.UnknownNamingException
            }
        }
    }

    private val activeDirectoryErrorCodes = listOf(
        ADLdapLoginService.DisabledAccount,
        ADLdapLoginService.AccountLocked,
        ADLdapLoginService.ExpiredPassword,
        ADLdapLoginService.PasswordNeedsReset,
        ADLdapLoginService.InvalidUsernameOrPassword,
    ).associateBy { it.code }

    companion object {
        private val VALID_USERNAME_REGEX = Regex("^[\\w-.!]+$")
        private val ACTIVE_DIRECTORY_SUB_ERROR_CODE_ERROR_MESSAGE_REGEX = Regex(".*data\\s([0-9a-f]{3,4}).*")
    }
}
