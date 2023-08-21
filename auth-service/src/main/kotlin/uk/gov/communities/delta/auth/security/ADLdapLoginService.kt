package uk.gov.communities.delta.auth.security

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.jetbrains.annotations.Blocking
import org.slf4j.LoggerFactory
import uk.gov.communities.delta.auth.config.LDAPConfig
import uk.gov.communities.delta.auth.services.LdapService
import uk.gov.communities.delta.auth.services.LdapUser
import javax.naming.AuthenticationException
import javax.naming.CommunicationException
import javax.naming.NamingException
import javax.naming.directory.InitialDirContext


/**
 * LDAP binds with Active Directory specific error handling
 */
interface IADLdapLoginService {
    suspend fun ldapLogin(username: String, password: String): LdapLoginResult


    sealed interface LdapLoginResult
    class LdapLoginSuccess(val user: LdapUser) : LdapLoginResult
    sealed class LdapLoginFailure : LdapLoginResult

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

class ADLdapLoginService(
    private val config: Configuration,
    private val ldapService: LdapService,
) : IADLdapLoginService {
    data class Configuration(val userDnFormat: String)

    private val logger = LoggerFactory.getLogger(this.javaClass)

    override suspend fun ldapLogin(username: String, password: String): IADLdapLoginService.LdapLoginResult {
        if (!username.matches(LDAPConfig.VALID_USERNAME_REGEX)) {
            logger.warn("Invalid username '{}'", username)
            return IADLdapLoginService.InvalidUsername
        }

        val userDn = config.userDnFormat.format(username)

        return withContext(Dispatchers.IO) {
            ldapBind(userDn, password)
        }
    }

    @Blocking
    private fun ldapBind(userDn: String, password: String): IADLdapLoginService.LdapLoginResult {
        var context: InitialDirContext? = null
        return try {
            context = ldapService.bind(userDn, password)
            val user = ldapService.mapUserFromContext(context, userDn)
            if (!user.accountEnabled) throw Exception("Logged in user '${user.cn}' is disabled, this should never happen")
            IADLdapLoginService.LdapLoginSuccess(user)
        } catch (e: NamingException) {
            logger.debug("LDAP login failed for user $userDn", e)
            handleLdapException(e)
        } finally {
            context?.close()
        }
    }

    private fun handleLdapException(e: NamingException): IADLdapLoginService.LdapLoginFailure {
        when (e) {
            is AuthenticationException -> {
                val subErrorCodeMatch = ACTIVE_DIRECTORY_SUB_ERROR_CODE_ERROR_MESSAGE_REGEX.find(e.message!!)
                if (subErrorCodeMatch != null) {
                    val subErrorCode = subErrorCodeMatch.groupValues[1]
                    return activeDirectoryErrorCodes.getOrElse(subErrorCode) {
                        logger.warn("Unknown AD sub error code $subErrorCode", e)
                        IADLdapLoginService.UnknownAdSubErrorCode
                    }
                }
                logger.warn("Authentication failure, no AD sub error code found", e)
                return IADLdapLoginService.UnknownAuthenticationFailure
            }

            is CommunicationException -> {
                logger.error("Failed to connect to LDAP server", e)
                return IADLdapLoginService.BadConnection
            }

            else -> {
                logger.warn("Unknown authentication failure", e)
                return IADLdapLoginService.UnknownNamingException
            }
        }
    }

    private val activeDirectoryErrorCodes = listOf(
        IADLdapLoginService.DisabledAccount,
        IADLdapLoginService.AccountLocked,
        IADLdapLoginService.ExpiredPassword,
        IADLdapLoginService.PasswordNeedsReset,
        IADLdapLoginService.InvalidUsernameOrPassword,
    ).associateBy { it.code }

    companion object {
        private val ACTIVE_DIRECTORY_SUB_ERROR_CODE_ERROR_MESSAGE_REGEX = Regex(".*data\\s([0-9a-f]{3,4}).*")
    }
}
