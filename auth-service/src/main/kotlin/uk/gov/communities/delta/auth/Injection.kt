package uk.gov.communities.delta.auth

import io.micrometer.cloudwatch2.CloudWatchConfig
import io.micrometer.cloudwatch2.CloudWatchMeterRegistry
import io.micrometer.core.instrument.Clock
import io.micrometer.core.instrument.Counter
import io.micrometer.core.instrument.simple.SimpleMeterRegistry
import org.slf4j.Logger
import software.amazon.awssdk.services.cloudwatch.CloudWatchAsyncClient
import uk.gov.communities.delta.auth.config.*
import uk.gov.communities.delta.auth.controllers.external.*
import uk.gov.communities.delta.auth.controllers.internal.*
import uk.gov.communities.delta.auth.repositories.DbPool
import uk.gov.communities.delta.auth.repositories.EmailRepository
import uk.gov.communities.delta.auth.repositories.LdapRepository
import uk.gov.communities.delta.auth.repositories.UserAuditTrailRepo
import uk.gov.communities.delta.auth.saml.SAMLTokenService
import uk.gov.communities.delta.auth.security.ADLdapLoginService
import uk.gov.communities.delta.auth.security.LdapAuthenticationService
import uk.gov.communities.delta.auth.services.*
import uk.gov.communities.delta.auth.services.sso.MicrosoftGraphService
import uk.gov.communities.delta.auth.services.sso.SSOLoginSessionStateService
import uk.gov.communities.delta.auth.services.sso.SSOOAuthClientProviderLookupService
import uk.gov.communities.delta.auth.tasks.*
import uk.gov.communities.delta.auth.utils.TimeSource
import java.time.Duration

@Suppress("MemberVisibilityCanBePrivate")
class Injection(
    val ldapConfig: LDAPConfig,
    val databaseConfig: DatabaseConfig,
    val clientConfig: ClientConfig,
    val deltaConfig: DeltaConfig,
    val emailConfig: EmailConfig,
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
                EmailConfig.fromEnv(),
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
        emailConfig.log(logger.atInfo())
        clientConfig.log(logger.atInfo())
        azureADSSOConfig.log(logger.atInfo())
        authServiceConfig.log(logger.atInfo())
    }

    fun close() {
        meterRegistry.close()
        dbPool.close()
    }

    fun registerShutdownHook() {
        Runtime.getRuntime().addShutdownHook(Thread { close() })
    }

    private val samlTokenService = SAMLTokenService()
    private val ldapRepository = LdapRepository(ldapConfig, LdapRepository.ObjectGUIDMode.OLD_MANGLED)
    private val ldapServiceUserBind = LdapServiceUserBind(ldapConfig, ldapRepository)
    private val userLookupService = UserLookupService(
        UserLookupService.Configuration(
            ldapConfig.deltaUserDnFormat,
            ldapConfig.authServiceUserDn,
            ldapConfig.authServiceUserPassword,
        ),
        ldapServiceUserBind,
        ldapRepository,
    )

    val dbPool = DbPool(databaseConfig)

    val userAuditTrailRepo = UserAuditTrailRepo()
    val userAuditService = UserAuditService(userAuditTrailRepo, dbPool)

    private val userService = UserService(ldapServiceUserBind, userLookupService, userAuditService)
    private val accessGroupsService = AccessGroupsService(ldapServiceUserBind, ldapConfig)
    private val groupService = GroupService(ldapServiceUserBind, ldapConfig, userAuditService)
    private val emailRepository = EmailRepository(emailConfig)

    val setPasswordTokenService = SetPasswordTokenService(dbPool, TimeSource.System)
    val resetPasswordTokenService = ResetPasswordTokenService(dbPool, TimeSource.System)
    val organisationService = OrganisationService(OrganisationService.makeHTTPClient(), deltaConfig)

    private val emailService = EmailService(
        emailConfig,
        deltaConfig, authServiceConfig,
        userAuditService,
        emailRepository,
    )

    val registrationService = RegistrationService(
        deltaConfig,
        emailConfig,
        ldapConfig,
        setPasswordTokenService,
        emailService,
        userService,
        userLookupService,
        groupService,
    )

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
    val loginRateLimitCounter: Counter = meterRegistry.counter("login.rateLimitedRequests")
    val successfulLoginCounter: Counter = meterRegistry.counter("login.successfulLogins")
    val ssoLoginCounter: Counter = meterRegistry.counter("login.ssoLogins")

    val registrationRateLimitCounter: Counter = meterRegistry.counter("registration.rateLimitedRequests")
    val setPasswordRateLimitCounter: Counter = meterRegistry.counter("setPassword.rateLimitedRequests")
    val resetPasswordRateLimitCounter: Counter = meterRegistry.counter("resetPassword.rateLimitedRequests")
    val forgotPasswordRateLimitCounter: Counter = meterRegistry.counter("forgotPassword.rateLimitedRequests")

    fun tasksMap(): Map<String, AuthServiceTask> {
        val deleteOldAuthCodesTask = DeleteOldAuthCodes(dbPool)
        val deleteOldDeltaSessionsTask = DeleteOldDeltaSessions(dbPool)
        val updateUserGuidMapTask = UpdateUserGUIDMap(ldapConfig, dbPool)
        val tasks = listOf(deleteOldAuthCodesTask, deleteOldDeltaSessionsTask, updateUserGuidMapTask)
        return tasks.associateBy { it.name }
    }

    fun taskRunner() = TaskRunner(meterRegistry)

    fun ldapServiceUserAuthenticationService(): LdapAuthenticationService {
        val adLoginService = ADLdapLoginService(
            ADLdapLoginService.Configuration(ldapConfig.serviceUserDnFormat),
            ldapRepository
        )
        return LdapAuthenticationService(adLoginService, ldapConfig.serviceUserRequiredGroupCn)
    }

    fun generateSAMLTokenController() = GenerateSAMLTokenController(samlTokenService)

    fun externalDeltaLoginController(): DeltaLoginController {
        val adLoginService = ADLdapLoginService(
            ADLdapLoginService.Configuration(ldapConfig.deltaUserDnFormat),
            ldapRepository
        )
        return DeltaLoginController(
            clientConfig.oauthClients,
            azureADSSOConfig,
            deltaConfig,
            adLoginService,
            authorizationCodeService,
            failedLoginCounter,
            successfulLoginCounter,
            userAuditService,
        )
    }

    fun externalDeltaUserRegisterController() = DeltaUserRegistrationController(
        deltaConfig,
        azureADSSOConfig,
        organisationService,
        registrationService,
        userAuditService,
    )

    fun externalDeltaSetPasswordController() = DeltaSetPasswordController(
        deltaConfig,
        ldapConfig,
        userService,
        setPasswordTokenService,
        userLookupService,
        emailService,
        userAuditService,
    )

    fun externalDeltaResetPasswordController() = DeltaResetPasswordController(
        deltaConfig,
        ldapConfig,
        emailConfig,
        authServiceConfig,
        userService,
        resetPasswordTokenService,
        userLookupService,
        emailService,
        userAuditService,
    )

    fun externalDeltaForgotPasswordController() = DeltaForgotPasswordController(
        deltaConfig,
        azureADSSOConfig,
        resetPasswordTokenService,
        setPasswordTokenService,
        userLookupService,
        emailService,
    )

    fun internalOAuthTokenController() = OAuthTokenController(
        clientConfig.oauthClients,
        authorizationCodeService,
        userLookupService,
        samlTokenService,
        oauthSessionService,
        accessGroupsService,
        organisationService,
        ::MemberOfToDeltaRolesMapper
    )

    fun refreshUserInfoController() = RefreshUserInfoController(
        userLookupService,
        samlTokenService,
        accessGroupsService,
        organisationService,
        ::MemberOfToDeltaRolesMapper
    )

    fun adminEmailController() = AdminEmailController(
        azureADSSOConfig,
        emailService,
        userLookupService,
        setPasswordTokenService,
        resetPasswordTokenService,
    )

    fun deltaOAuthLoginController() = DeltaSSOLoginController(
        deltaConfig,
        clientConfig,
        azureADSSOConfig,
        ssoLoginStateService,
        userLookupService,
        authorizationCodeService,
        microsoftGraphService,
        registrationService,
        organisationService,
        ssoLoginCounter,
        userAuditService,
    )

    fun fetchUserAuditController() = FetchUserAuditController(
        userLookupService,
        userAuditService,
    )

    fun adminUserCreationController() = AdminUserCreationController(
        ldapConfig,
        azureADSSOConfig,
        emailConfig,
        userLookupService,
        userService,
        groupService,
        emailService,
        setPasswordTokenService,
    )

    fun adminEditUserController() = AdminEditUserController(
        userLookupService,
        userService,
        groupService,
    )

    fun adminGetUserController() = AdminGetUserController(
        userLookupService,
        organisationService,
        accessGroupsService,
        ::MemberOfToDeltaRolesMapper,
    )

    fun editRolesController() = EditRolesController(
        userLookupService,
        groupService,
        organisationService,
        accessGroupsService,
        ::MemberOfToDeltaRolesMapper,
    )

    fun editAccessGroupsController() = EditAccessGroupsController(
        userLookupService,
        groupService,
        organisationService,
        accessGroupsService,
        ::MemberOfToDeltaRolesMapper,
    )
}
