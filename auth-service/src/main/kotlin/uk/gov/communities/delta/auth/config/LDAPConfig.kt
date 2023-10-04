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
    val domainRealm: String,
) {
    companion object {
        fun fromEnv(): LDAPConfig = LDAPConfig(
            deltaLdapUrl = Env.getRequiredOrDevFallback("DELTA_LDAP_URL", "ldaps://dluhctest.local:2636"),
            serviceUserDnFormat = Env.getRequiredOrDevFallback(
                "LDAP_SERVICE_USER_DN_FORMAT",
                "CN=%s,OU=Users,OU=dluhctest,DC=dluhctest,DC=local"
            ),
            deltaUserDnFormat = Env.getRequiredOrDevFallback(
                "LDAP_DELTA_USER_DN_FORMAT",
                "CN=%s,CN=Datamart,OU=Users,OU=dluhctest,DC=dluhctest,DC=local"
            ),
            groupDnFormat = Env.getRequiredOrDevFallback(
                "LDAP_GROUP_DN_FORMAT",
                "CN=%s,OU=Groups,OU=dluhctest,DC=dluhctest,DC=local"
            ),
            serviceUserRequiredGroupCn = "dluhc-service-users",
            authServiceUserCn = Env.getEnv("LDAP_AUTH_SERVICE_USER") ?: "auth-service.app",
            authServiceUserPassword = Env.getRequired("LDAP_AUTH_SERVICE_USER_PASSWORD"),
            domainRealm = Env.getRequiredOrDevFallback("LDAP_DOMAIN_REALM", "dluhctest.local")
        )
        val VALID_EMAIL_REGEX = Regex("^[\\w-+.']+@([\\w-']+\\.)+[\\w-]{2,4}$")
        val VALID_USERNAME_REGEX = Regex("^[\\w-+.!']+$")
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
