package uk.gov.communities.delta.auth.config

import org.slf4j.spi.LoggingEventBuilder

class LDAPConfig {
    companion object {
        val DELTA_LDAP_URL = System.getenv("DELTA_LDAP_URL") ?: "ldap://localhost:2389"
        val LDAP_SERVICE_USER_DN_FORMAT =
            System.getenv("LDAP_SERVICE_USER_DN_FORMAT") ?: "CN=%s,OU=Users,OU=dluhctest,DC=dluhctest,DC=local"
        val LDAP_DELTA_USER_DN_FORMAT =
            System.getenv("LDAP_DELTA_USER_DN_FORMAT")
                ?: "CN=%s,CN=Datamart,OU=Users,OU=dluhctest,DC=dluhctest,DC=local"
        val LDAP_GROUP_DN_FORMAT =
            System.getenv("LDAP_GROUP_DN_FORMAT") ?: "CN=%s,OU=Groups,OU=dluhctest,DC=dluhctest,DC=local"
        const val SERVICE_USER_GROUP_CN = "dluhc-service-users"
        private val LDAP_AUTH_SERVICE_USER = System.getenv("LDAP_AUTH_SERVICE_USER") ?: "delta.app"
        val ldapAuthServiceUserDn = LDAP_SERVICE_USER_DN_FORMAT.format(LDAP_AUTH_SERVICE_USER)
        val LDAP_AUTH_SERVICE_USER_PASSWORD = System.getenv("LDAP_AUTH_SERVICE_USER_PASSWORD") ?: throw Exception("Environment variable LDAP_AUTH_SERVICE_USER_PASSWORD is required")

        val VALID_USERNAME_REGEX = Regex("^[\\w-.!]+$")

        fun log(logger: LoggingEventBuilder) {
            logger
                .addKeyValue("DELTA_LDAP_URL", DELTA_LDAP_URL)
                .addKeyValue("LDAP_SERVICE_USER_DN_FORMAT", LDAP_SERVICE_USER_DN_FORMAT)
                .addKeyValue("LDAP_DELTA_USER_DN_FORMAT", LDAP_DELTA_USER_DN_FORMAT)
                .addKeyValue("LDAP_GROUP_DN_FORMAT", LDAP_GROUP_DN_FORMAT)
                .addKeyValue("LDAP_AUTH_SERVICE_USER", LDAP_AUTH_SERVICE_USER)
                .log("LDAP config")
        }
    }
}
