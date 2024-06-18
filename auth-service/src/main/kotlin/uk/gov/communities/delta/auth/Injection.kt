package uk.gov.communities.delta.auth

import io.micrometer.cloudwatch2.CloudWatchConfig
import io.micrometer.cloudwatch2.CloudWatchMeterRegistry
import io.micrometer.core.instrument.Clock
import io.micrometer.core.instrument.Counter
import io.micrometer.core.instrument.simple.SimpleMeterRegistry
import io.opentelemetry.api.trace.SpanKind
import io.opentelemetry.context.Context
import org.slf4j.Logger
import software.amazon.awssdk.services.cloudwatch.CloudWatchAsyncClient
import uk.gov.communities.delta.auth.config.*
import uk.gov.communities.delta.auth.controllers.external.*
import uk.gov.communities.delta.auth.controllers.internal.*
import uk.gov.communities.delta.auth.plugins.monitoring.SpanFactory
import uk.gov.communities.delta.auth.plugins.monitoring.initOpenTelemetry
import uk.gov.communities.delta.auth.repositories.*
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
    val tracingConfig: TracingConfig,
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
                TracingConfig.fromEnv(),
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
        tracingConfig.log(logger.atInfo())
    }

    fun close() {
        meterRegistry.close()
        dbPool.close()
    }

    fun registerShutdownHook() {
        Runtime.getRuntime().addShutdownHook(Thread { close() })
    }

    val openTelemetry = initOpenTelemetry(tracingConfig)

    private val samlTracer = openTelemetry.getTracer("delta.auth.samlTokenGenerator")
    private val ldapTracer = openTelemetry.getTracer("delta.auth.ldap")
    private val ldapSpanFactory: SpanFactory = {
        ldapTracer.spanBuilder(it).setParent(Context.current())
            .setAttribute("peer.service", "ActiveDirectory")
            .setSpanKind(SpanKind.CLIENT)
            .setAttribute("delta.request-to", "AD-ldap")
    }

    private val samlTokenService = SAMLTokenService(samlTracer)
    val dbPool = DbPool(databaseConfig, openTelemetry)

    private val ldapRepository = LdapRepository(ldapConfig, LdapRepository.ObjectGUIDMode.NEW_JAVA_UUID_STRING)
    private val ldapServiceUserBind = LdapServiceUserBind(ldapConfig, ldapRepository, ldapSpanFactory)

    val userAuditTrailRepo = UserAuditTrailRepo()
    val userAuditService = UserAuditService(userAuditTrailRepo, dbPool)

    private val accessGroupsService = AccessGroupsService(ldapServiceUserBind, ldapConfig)
    private val groupService = GroupService(ldapServiceUserBind, ldapConfig, userAuditService)
    private val emailRepository = EmailRepository(emailConfig)

    val setPasswordTokenService = SetPasswordTokenService(dbPool, TimeSource.System)
    val resetPasswordTokenService = ResetPasswordTokenService(dbPool, TimeSource.System)
    val organisationService = OrganisationService(OrganisationService.makeHTTPClient(openTelemetry), deltaConfig)

    private val userLookupService = UserLookupService(
        ldapConfig.deltaUserDnFormat,
        ldapServiceUserBind,
        ldapRepository,
        organisationService,
        accessGroupsService,
        ::MemberOfToDeltaRolesMapper
    )
    private val userGUIDMapRepo = UserGUIDMapRepo()
    private val userGUIDMapService = UserGUIDMapService(userGUIDMapRepo, userLookupService, dbPool)
    private val userService =
        UserService(
            ldapServiceUserBind,
            userLookupService,
            userGUIDMapService,
            userAuditService,
            ldapConfig,
            ldapRepository
        )

    private val deltaApiTokenService = DeltaApiTokenService(dbPool, TimeSource.System, userAuditService)

    private val emailService = EmailService(
        emailConfig,
        deltaConfig,
        authServiceConfig,
        userAuditService,
        emailRepository,
    )

    private val accessGroupDCLGMembershipUpdateEmailService =
        AccessGroupDCLGMembershipUpdateEmailService(ldapServiceUserBind, ldapConfig, emailService, emailConfig)

    val registrationService = RegistrationService(
        emailConfig,
        ldapConfig,
        setPasswordTokenService,
        emailService,
        userService,
        userLookupService,
        userGUIDMapService,
        groupService,
    )

    val authorizationCodeService = AuthorizationCodeService(dbPool, TimeSource.System)
    val oauthSessionService = OAuthSessionService(dbPool, TimeSource.System, userGUIDMapRepo)
    val ssoLoginStateService = SSOLoginSessionStateService()
    val ssoOAuthClientProviderLookupService =
        SSOOAuthClientProviderLookupService(azureADSSOConfig, ssoLoginStateService)
    val microsoftGraphService = MicrosoftGraphService(openTelemetry)
    val deltaUserDetailsRequestMapper = DeltaUserPermissionsRequestMapper(organisationService, accessGroupsService)
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
        val deleteOldApiTokensTask = DeleteOldApiTokens(dbPool)
        val updateUserGuidMapTask = UpdateUserGUIDMap(ldapConfig, dbPool)
        val tasks =
            listOf(deleteOldAuthCodesTask, deleteOldDeltaSessionsTask, deleteOldApiTokensTask, updateUserGuidMapTask)
        return tasks.associateBy { it.name }
    }

    fun taskRunner() = TaskRunner(meterRegistry)

    fun ldapServiceUserAuthenticationService(): LdapAuthenticationService {
        val adLoginService = ADLdapLoginService(
            ADLdapLoginService.Configuration(ldapConfig.serviceUserDnFormat),
            ldapRepository, ldapSpanFactory
        )
        return LdapAuthenticationService(adLoginService, ldapConfig.serviceUserRequiredGroupCn)
    }

    fun generateSAMLTokenController() = GenerateSAMLTokenController(samlTokenService)

    fun externalDeltaLoginController(): DeltaLoginController {
        val adLoginService = ADLdapLoginService(
            ADLdapLoginService.Configuration(ldapConfig.deltaUserDnFormat),
            ldapRepository, ldapSpanFactory
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
    )

    fun externalDeltaSetPasswordController() = DeltaSetPasswordController(
        deltaConfig,
        userService,
        setPasswordTokenService,
        userLookupService,
        userGUIDMapService,
        emailService,
        userAuditService,
    )

    fun externalDeltaResetPasswordController() = DeltaResetPasswordController(
        deltaConfig,
        userService,
        resetPasswordTokenService,
        userLookupService,
        userGUIDMapService,
        emailService,
        userAuditService,
    )

    fun externalDeltaForgotPasswordController() = DeltaForgotPasswordController(
        deltaConfig,
        azureADSSOConfig,
        resetPasswordTokenService,
        setPasswordTokenService,
        userLookupService,
        userGUIDMapService,
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

    fun externalDeltaApiTokenController(): ExternalDeltaApiTokenController {
        val adLoginService = ADLdapLoginService(
            ADLdapLoginService.Configuration(ldapConfig.deltaUserDnFormat),
            ldapRepository, ldapSpanFactory
        )
        return ExternalDeltaApiTokenController(deltaApiTokenService, adLoginService)
    }

    fun internalDeltaApiTokenController() =
        InternalDeltaApiTokenController(deltaApiTokenService, samlTokenService, userLookupService)

    fun refreshUserInfoController() = RefreshUserInfoController(
        userLookupService,
        userGUIDMapService,
        samlTokenService,
        accessGroupsService,
        organisationService,
        ::MemberOfToDeltaRolesMapper,
        oauthSessionService,
        userAuditService
    )

    fun adminEmailController() = AdminEmailController(
        azureADSSOConfig,
        emailService,
        userLookupService,
        userGUIDMapService,
        setPasswordTokenService,
        resetPasswordTokenService,
    )

    fun deltaOAuthLoginController() = DeltaSSOLoginController(
        deltaConfig,
        clientConfig,
        azureADSSOConfig,
        ssoLoginStateService,
        userLookupService,
        userGUIDMapService,
        authorizationCodeService,
        microsoftGraphService,
        registrationService,
        organisationService,
        ssoLoginCounter,
        userAuditService,
    )

    fun fetchUserAuditController() = FetchUserAuditController(
        userLookupService,
        userGUIDMapService,
        userAuditService,
    )

    fun adminUserCreationController() = AdminUserCreationController(
        ldapConfig,
        azureADSSOConfig,
        userLookupService,
        userGUIDMapService,
        userService,
        groupService,
        emailService,
        setPasswordTokenService,
        deltaUserDetailsRequestMapper,
        accessGroupDCLGMembershipUpdateEmailService
    )

    fun adminEditUserController() = AdminEditUserController(
        userLookupService,
        userGUIDMapService,
        userService,
        groupService,
        deltaUserDetailsRequestMapper,
        accessGroupDCLGMembershipUpdateEmailService,
    )

    fun adminGetUserController() = AdminGetUserController(
        userLookupService,
        userGUIDMapService,
    )

    fun adminEditEmailController() = AdminEditUserEmailController(
        userLookupService,
        userGUIDMapService,
        userService,
    )

    fun adminEnableDisableUserController() = AdminEnableDisableUserController(
        azureADSSOConfig,
        userLookupService,
        userGUIDMapService,
        userService,
        setPasswordTokenService,
        userAuditService,
    )


    fun adminResetMfaTokenController() = AdminResetMfaTokenController(
        userLookupService,
        userGUIDMapService,
        userService,
    )

    fun adminEditUserNotificationStatusController() = AdminEditUserNotificationStatusController(
        userLookupService,
        userGUIDMapService,
        userService,
    )

    fun editAccessGroupsController() = EditAccessGroupsController(
        userLookupService,
        userGUIDMapService,
        groupService,
        organisationService,
        accessGroupsService,
        ::MemberOfToDeltaRolesMapper,
        accessGroupDCLGMembershipUpdateEmailService
    )

    fun editLdapGroupsController() = EditLdapGroupsController(
        groupService,
        userLookupService,
        userGUIDMapService,
    )

    fun editUserDetailsController() = EditUserDetailsController(
        userLookupService,
        userService,
    )

    fun editRolesController() = EditRolesController(userLookupService, groupService)

    fun editOrganisationsController() =
        EditOrganisationsController(userLookupService, groupService, organisationService)
}
