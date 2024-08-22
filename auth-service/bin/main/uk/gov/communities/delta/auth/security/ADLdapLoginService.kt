package uk.gov.communities.delta.auth.security

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.jetbrains.annotations.Blocking
import org.slf4j.LoggerFactory
import uk.gov.communities.delta.auth.config.LDAPConfig
import uk.gov.communities.delta.auth.plugins.SpanFactory
import uk.gov.communities.delta.auth.repositories.LdapRepository
import uk.gov.communities.delta.auth.repositories.LdapUser
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
    private val ldapRepository: LdapRepository,
    private val ldapSpanFactory: SpanFactory,
) : IADLdapLoginService {
    data class Configuration(val userDnFormat: String)

    private val logger = LoggerFactory.getLogger(this.javaClass)

    override suspend fun ldapLogin(username: String, password: String): IADLdapLoginService.LdapLoginResult {
        if (username.length > 1000) {
            logger.warn("Username too long {}", username.length)
            return IADLdapLoginService.InvalidUsername
        }
        if (password.length > 1000) {
            logger.warn("Password too long {}", password.length)
            return IADLdapLoginService.InvalidUsernameOrPassword
        }

        if (!username.matches(LDAPConfig.VALID_USER_CN_REGEX)) {
            logger.atWarn().addKeyValue("username", username).log("Invalid username")
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
        val span = ldapSpanFactory("AD-ldap-user-bind").startSpan()
        return try {
            context = ldapRepository.bind(userDn, password)
            val user = ldapRepository.mapUserFromContext(context, userDn)
            if (!user.accountEnabled) throw Exception("Logged in user '${user.getGUID()}' is disabled, this should never happen")
            IADLdapLoginService.LdapLoginSuccess(user)
        } catch (e: NamingException) {
            logger.debug("LDAP login failed for user $userDn", e)
            handleLdapException(e)
        } finally {
            context?.close()
            span.end()
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
