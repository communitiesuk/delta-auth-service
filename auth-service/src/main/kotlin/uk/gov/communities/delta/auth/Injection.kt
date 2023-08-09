package uk.gov.communities.delta.auth

import org.slf4j.Logger
import uk.gov.communities.delta.auth.config.*
import uk.gov.communities.delta.auth.controllers.external.DeltaLoginController
import uk.gov.communities.delta.auth.controllers.external.DeltaSSOLoginController
import uk.gov.communities.delta.auth.controllers.internal.GenerateSAMLTokenController
import uk.gov.communities.delta.auth.controllers.internal.OAuthTokenController
import uk.gov.communities.delta.auth.controllers.internal.RefreshUserInfoController
import uk.gov.communities.delta.auth.saml.SAMLTokenService
import uk.gov.communities.delta.auth.security.ADLdapLoginService
import uk.gov.communities.delta.auth.security.LdapAuthenticationService
import uk.gov.communities.delta.auth.services.*
import uk.gov.communities.delta.auth.services.sso.MicrosoftGraphService
import uk.gov.communities.delta.auth.services.sso.SSOLoginSessionStateService
import uk.gov.communities.delta.auth.services.sso.SSOOAuthClientProviderLookupService

@Suppress("MemberVisibilityCanBePrivate")
class Injection (
    val ldapConfig: LDAPConfig,
    val databaseConfig: DatabaseConfig,
    val clientConfig: ClientConfig,
    val deltaConfig: DeltaConfig,
    val azureADSSOConfig: AzureADSSOConfig,
    val authServiceConfig: AuthServiceConfig,
) {
    companion object {
        lateinit var instance: Injection
        fun startupInitFromEnvironment() {
            if (::instance.isInitialized) {
                throw Exception("Already initialised")
            }
            val deltaConfig = DeltaConfig.fromEnv()
            instance = Injection(
                LDAPConfig.fromEnv(),
                DatabaseConfig.fromEnv(),
                ClientConfig.fromEnv(deltaConfig),
                deltaConfig,
                AzureADSSOConfig.fromEnv(),
                AuthServiceConfig.fromEnv(),
            )
        }
    }

    fun logConfig(logger: Logger) {
        ldapConfig.log(logger.atInfo())
        databaseConfig.log(logger.atInfo())
        deltaConfig.log(logger.atInfo())
        clientConfig.log(logger.atInfo())
        azureADSSOConfig.log(logger.atInfo())
        authServiceConfig.log(logger.atInfo())
    }

    private val samlTokenService = SAMLTokenService()
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
    val authorizationCodeService = AuthorizationCodeService(dbPool)
    val oAuthSessionService = OAuthSessionService(dbPool)
    val ssoLoginStateService = SSOLoginSessionStateService()
    val ssoOAuthClientProviderLookupService = SSOOAuthClientProviderLookupService(azureADSSOConfig, ssoLoginStateService)
    val microsoftGraphService = MicrosoftGraphService()

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
        return DeltaLoginController(clientConfig.oauthClients, azureADSSOConfig, deltaConfig, adLoginService, authorizationCodeService)
    }

    fun internalOAuthTokenController() = OAuthTokenController(
        clientConfig.oauthClients,
        authorizationCodeService,
        userLookupService,
        samlTokenService,
        oAuthSessionService,
    )

    fun refreshUserInfoController() = RefreshUserInfoController(userLookupService, samlTokenService)

    fun deltaOAuthLoginController() =
        DeltaSSOLoginController(deltaConfig, clientConfig, azureADSSOConfig, ssoLoginStateService, userLookupService, authorizationCodeService, microsoftGraphService)
}
