package uk.gov.communities.delta.auth.config

import org.slf4j.spi.LoggingEventBuilder

class LDAPConfig {
    companion object {
        val LDAP_URL = System.getenv("DELTA_LDAP_URL") ?: "ldap://localhost:2389"
        val LDAP_SERVICE_USER_DN_FORMAT =
            System.getenv("DELTA_LDAP_USER_DN_FORMAT") ?: "CN=%s,OU=Users,OU=dluhctest,DC=dluhctest,DC=local"
        val LDAP_GROUP_DN_FORMAT =
            System.getenv("DELTA_LDAP_DN_FORMAT") ?: "CN=%s,OU=Groups,OU=dluhctest,DC=dluhctest,DC=local"

        fun log(logger: LoggingEventBuilder) {
            logger
                .addKeyValue("LDAP_URL", LDAP_URL)
                .addKeyValue("LDAP_SERVICE_USER_DN_FORMAT", LDAP_SERVICE_USER_DN_FORMAT)
                .addKeyValue("LDAP_GROUP_DN_FORMAT", LDAP_GROUP_DN_FORMAT)
                .log("LDAP config")
        }
    }
}
