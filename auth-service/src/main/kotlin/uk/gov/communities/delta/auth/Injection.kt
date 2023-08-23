package uk.gov.communities.delta.auth

import io.micrometer.cloudwatch2.CloudWatchConfig
import io.micrometer.cloudwatch2.CloudWatchMeterRegistry
import io.micrometer.core.instrument.Clock
import io.micrometer.core.instrument.Counter
import io.micrometer.core.instrument.simple.SimpleMeterRegistry
import org.slf4j.Logger
import software.amazon.awssdk.services.cloudwatch.CloudWatchAsyncClient
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
import uk.gov.communities.delta.auth.tasks.DeleteOldAuthCodes
import uk.gov.communities.delta.auth.tasks.DeleteOldDeltaSessions
import uk.gov.communities.delta.auth.tasks.TaskRunner
import uk.gov.communities.delta.auth.utils.TimeSource
import java.time.Duration

@Suppress("MemberVisibilityCanBePrivate")
class Injection(
    val ldapConfig: LDAPConfig,
    val databaseConfig: DatabaseConfig,
    val clientConfig: ClientConfig,
    val deltaConfig: DeltaConfig,
    val azureADSSOConfig: AzureADSSOConfig,
    val authServiceConfig: AuthServiceConfig,
) {
    companion object {
        lateinit var instance: Injection
        fun startupInitFromEnvironment(): Injection {
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
            return instance
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

    fun close() {
        meterRegistry.close()
        dbPool.close()
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
    val authorizationCodeService = AuthorizationCodeService(dbPool, TimeSource.System)
    val oauthSessionService = OAuthSessionService(dbPool, TimeSource.System)
    val ssoLoginStateService = SSOLoginSessionStateService()
    val ssoOAuthClientProviderLookupService =
        SSOOAuthClientProviderLookupService(azureADSSOConfig, ssoLoginStateService)
    val microsoftGraphService = MicrosoftGraphService()
    val meterRegistry =
        if (authServiceConfig.metricsNamespace.isNullOrEmpty()) SimpleMeterRegistry() else CloudWatchMeterRegistry(
            object : CloudWatchConfig {
                private val configuration = mapOf(
                    "cloudwatch.namespace" to authServiceConfig.metricsNamespace,
                    "cloudwatch.step" to Duration.ofMinutes(1).toString()
                )

                override fun get(key: String): String? = configuration[key]
            },
            Clock.SYSTEM,
            CloudWatchAsyncClient.create()
        )
    val failedLoginCounter: Counter = meterRegistry.counter("login.failedLogins")
    val rateLimitCounter: Counter = meterRegistry.counter("login.rateLimitedRequests")
    val successfulLoginCounter: Counter = meterRegistry.counter("login.successfulLogins")

    val deleteOldAuthCodesTask = DeleteOldAuthCodes(dbPool)
    val deleteOldDeltaSessionsTask = DeleteOldDeltaSessions(dbPool)
    val tasks = listOf(deleteOldAuthCodesTask, deleteOldDeltaSessionsTask)
    fun tasksMap() = tasks.associateBy { it.name }

    fun taskRunner() = TaskRunner(meterRegistry)

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
        return DeltaLoginController(
            clientConfig.oauthClients,
            azureADSSOConfig,
            deltaConfig,
            adLoginService,
            authorizationCodeService,
            failedLoginCounter,
            successfulLoginCounter
        )
    }

    fun internalOAuthTokenController() = OAuthTokenController(
        clientConfig.oauthClients,
        authorizationCodeService,
        userLookupService,
        samlTokenService,
        oauthSessionService,
    )

    fun refreshUserInfoController() = RefreshUserInfoController(userLookupService, samlTokenService)

    fun deltaOAuthLoginController() =
        DeltaSSOLoginController(
            deltaConfig,
            clientConfig,
            azureADSSOConfig,
            ssoLoginStateService,
            userLookupService,
            authorizationCodeService,
            microsoftGraphService
        )
}
