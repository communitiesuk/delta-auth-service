package uk.gov.communities.delta.auth.config

import org.slf4j.spi.LoggingEventBuilder

data class LDAPConfig(
    val deltaLdapUrl: String,
    val serviceUserDnFormat: String,
    val deltaUserDnFormat: String,
    val groupDnFormat: String,
    val serviceUserRequiredGroupCn: String,
    val authServiceUserCn: String,
    val authServiceUserPassword: String,
) {
    companion object {
        fun fromEnv(): LDAPConfig = LDAPConfig(
            deltaLdapUrl = System.getenv("DELTA_LDAP_URL") ?: "ldap://localhost:2389",
            serviceUserDnFormat = System.getenv("LDAP_SERVICE_USER_DN_FORMAT")
                ?: "CN=%s,OU=Users,OU=dluhctest,DC=dluhctest,DC=local",
            deltaUserDnFormat = System.getenv("LDAP_DELTA_USER_DN_FORMAT")
                ?: "CN=%s,CN=Datamart,OU=Users,OU=dluhctest,DC=dluhctest,DC=local",
            groupDnFormat = System.getenv("LDAP_GROUP_DN_FORMAT")
                ?: "CN=%s,OU=Groups,OU=dluhctest,DC=dluhctest,DC=local",
            serviceUserRequiredGroupCn = "dluhc-service-users",
            authServiceUserCn = System.getenv("LDAP_AUTH_SERVICE_USER") ?: "auth-service.app",
            authServiceUserPassword = System.getenv("LDAP_AUTH_SERVICE_USER_PASSWORD")
                ?: throw Exception("Environment variable LDAP_AUTH_SERVICE_USER_PASSWORD is required"),
        )

        val VALID_USERNAME_REGEX = Regex("^[\\w-.!]+$")
    }

    val authServiceUserDn = serviceUserDnFormat.format(authServiceUserCn)

    fun log(logger: LoggingEventBuilder) {
        logger
            .addKeyValue("DELTA_LDAP_URL", deltaLdapUrl)
            .addKeyValue("LDAP_SERVICE_USER_DN_FORMAT", serviceUserDnFormat)
            .addKeyValue("LDAP_DELTA_USER_DN_FORMAT", deltaUserDnFormat)
            .addKeyValue("LDAP_GROUP_DN_FORMAT", groupDnFormat)
            .addKeyValue("LDAP_AUTH_SERVICE_USER", authServiceUserCn)
            .log("LDAP config")
    }
}
