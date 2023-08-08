package uk.gov.communities.delta.auth

import org.slf4j.Logger
import uk.gov.communities.delta.auth.config.*
import uk.gov.communities.delta.auth.controllers.external.DeltaLoginController
import uk.gov.communities.delta.auth.controllers.external.DeltaOAuthLoginController
import uk.gov.communities.delta.auth.controllers.internal.GenerateSAMLTokenController
import uk.gov.communities.delta.auth.controllers.internal.OAuthTokenController
import uk.gov.communities.delta.auth.controllers.internal.RefreshUserInfoController
import uk.gov.communities.delta.auth.saml.SAMLTokenService
import uk.gov.communities.delta.auth.security.ADLdapLoginService
import uk.gov.communities.delta.auth.security.LdapAuthenticationService
import uk.gov.communities.delta.auth.security.OAuthClientProviderLookupService
import uk.gov.communities.delta.auth.security.SSOLoginStateService
import uk.gov.communities.delta.auth.services.*

class Injection (
    val ldapConfig: LDAPConfig,
    val databaseConfig: DatabaseConfig,
    val clientConfig: ClientConfig,
    val deltaConfig: DeltaConfig,
    val azureADSSOConfig: AzureADSSOConfig,
    val serviceConfig: ServiceConfig,
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
                ServiceConfig.fromEnv(),
            )
        }
    }

    fun logConfig(logger: Logger) {
        ldapConfig.log(logger.atInfo())
        databaseConfig.log(logger.atInfo())
        deltaConfig.log(logger.atInfo())
        clientConfig.log(logger.atInfo())
        azureADSSOConfig.log(logger.atInfo())
        serviceConfig.log(logger.atInfo())
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
    private val authorizationCodeService = AuthorizationCodeService(dbPool)
    val oAuthSessionService = OAuthSessionService(dbPool)
    val ssoLoginStateService = SSOLoginStateService()
    val oauthClientProviderLookupService = OAuthClientProviderLookupService(azureADSSOConfig, ssoLoginStateService)

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
        DeltaOAuthLoginController(deltaConfig, clientConfig, azureADSSOConfig, ssoLoginStateService, userLookupService, authorizationCodeService)
}
