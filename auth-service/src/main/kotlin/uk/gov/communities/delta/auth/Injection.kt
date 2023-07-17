package uk.gov.communities.delta.auth

import org.slf4j.Logger
import uk.gov.communities.delta.auth.config.*
import uk.gov.communities.delta.auth.controllers.external.DeltaLoginController
import uk.gov.communities.delta.auth.controllers.internal.GenerateSAMLTokenController
import uk.gov.communities.delta.auth.controllers.internal.OAuthTokenController
import uk.gov.communities.delta.auth.saml.SAMLTokenService
import uk.gov.communities.delta.auth.security.ADLdapLoginService
import uk.gov.communities.delta.auth.security.LdapAuthenticationService
import uk.gov.communities.delta.auth.services.AuthorizationCodeService
import uk.gov.communities.delta.auth.services.DbPool
import uk.gov.communities.delta.auth.services.LdapService
import uk.gov.communities.delta.auth.services.UserLookupService

class Injection (
    val ldapConfig: LDAPConfig,
    val databaseConfig: DatabaseConfig,
    val clientConfig: ClientConfig,
    val deltaConfig: DeltaConfig,
) {
    companion object {
        lateinit var instance: Injection
        fun startupInitFromEnvironment() {
            if (::instance.isInitialized) {
                throw Exception("Already initialised")
            }
            instance = Injection(
                LDAPConfig.fromEnv(),
                DatabaseConfig.fromEnv(),
                ClientConfig.fromEnv(),
                DeltaConfig.fromEnv(),
            )
        }
    }

    fun logConfig(logger: Logger) {
        ldapConfig.log(logger.atInfo())
        databaseConfig.log(logger.atInfo())
        deltaConfig.log(logger.atInfo())
    }

    private val samlTokenService = SAMLTokenService(SAMLConfig.getSAMLSigningCredentials())
    private val ldapService = LdapService(
        LdapService.Configuration(
            ldapUrl = ldapConfig.deltaLdapUrl,
            groupDnFormat = ldapConfig.groupDnFormat
        )
    )
    private val userLookupService = UserLookupService(
        UserLookupService.Configuration(
            ldapConfig.deltaUserDnFormat,
            ldapConfig.authServiceUserDn,
            ldapConfig.authServiceUserPassword,
        ),
        ldapService
    )

    val dbPool = DbPool(databaseConfig)
    private val authorizationCodeService = AuthorizationCodeService(dbPool)

    fun ldapServiceUserAuthenticationService(): LdapAuthenticationService {
        val adLoginService = ADLdapLoginService(
            ADLdapLoginService.Configuration(ldapConfig.serviceUserDnFormat),
            ldapService
        )
        return LdapAuthenticationService(adLoginService, ldapConfig.serviceUserRequiredGroupCn)
    }

    fun generateSAMLTokenController() = GenerateSAMLTokenController(samlTokenService)

    fun externalDeltaLoginController(): DeltaLoginController {
        val adLoginService = ADLdapLoginService(
            ADLdapLoginService.Configuration(ldapConfig.deltaUserDnFormat),
            ldapService
        )
        return DeltaLoginController(clientConfig.deltaWebsite, deltaConfig, adLoginService, authorizationCodeService)
    }

    fun internalOAuthTokenController() = OAuthTokenController(
        clientConfig,
        authorizationCodeService,
        userLookupService,
        samlTokenService,
    )
}
