package uk.gov.communities.delta.auth.config

import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import org.slf4j.spi.LoggingEventBuilder

@Serializable
data class AzureADSSOClient(
    // Used in the login + callback urls /delta/oauth/<internalClientId>/callback
    val internalId: String,
    val azTenantId: String,
    val azClientId: String,
    val azClientSecret: String,
    // Only allows the SSO provider to log users in under this domain. Must include the "@" prefix.
    val emailDomain: String,
    // Accept JWTs with this as the email domain, but log in the user with the above domain in their CN instead.
    // This is a workaround for DLUHC users having "@levellingup.gov.uk" as their username in Delta,
    // but "@communities.gov.uk" as their username in Azure AD.
    val convertFromEmailDomain: String? = null,
    // Force users with a matching email domain to use the SSO flow rather than username + password
    // If SSO is required users cannot register normally or reset their password, an accounts will automatically be
    // created when they first sign in.
    val required: Boolean = false,
    // Object ID of a group in Azure AD that all SSO users must be a member of to log in, or null to allow all users
    val requiredGroupId: String? = null,
    // Group that Admins (DELTA_ADMIN_ROLES) must be part of or their login will be rejected, or null to allow all users
    val requiredAdminGroupId: String? = null,
    // User visible text to display on SSO login button, or null to hide button
    val buttonText: String? = null,
) {
    override fun toString() = "AzureADSSOClient($internalId, $azTenantId, $azClientId)"

    init {
        if (!emailDomain.startsWith("@")) {
            throw Exception("AzureADSSOConfig emailDomain must start with @")
        }
        if (convertFromEmailDomain != null && !convertFromEmailDomain.startsWith("@")) {
            throw Exception("AzureADSSOConfig convertFromEmailDomain must start with @ if provided")
        }
    }
}

class AzureADSSOConfig(val ssoClients: List<AzureADSSOClient>) {
    companion object {
        fun fromEnv(): AzureADSSOConfig {
            val json = Env.getEnv("AZ_SSO_CLIENTS_JSON") ?: return AzureADSSOConfig(emptyList())
            val parsed = Json.decodeFromString<List<AzureADSSOClient>>(json)
            return AzureADSSOConfig(parsed)
        }

        val DELTA_ADMIN_ROLES: List<String> = listOf(
            "datamart-delta-admin",
            "datamart-delta-dataset-admins",
            "datamart-delta-local-admins",
            "datamart-delta-read-only-admin"
        )
    }

    fun log(logger: LoggingEventBuilder) {
        logger.log("Azure AD SSO clients {}", ssoClients)
    }
}
