package uk.gov.communities.delta.auth

class Config {
    companion object {
        val LDAP_URL = System.getenv("DELTA_LDAP_URL") ?: "ldap://localhost:2389"
        // TODO: Remove CN=Datamart
        val LDAP_SERVICE_USER_DN_FORMAT = System.getenv("DELTA_LDAP_USER_DN_FORMAT") ?: "CN=%s,CN=Datamart,OU=Users,OU=dluhctest,DC=dluhctest,DC=local"
        val LDAP_GROUP_DN_FORMAT =  System.getenv("DELTA_LDAP_DN_FORMAT") ?: "CN=%s,OU=Groups,OU=dluhctest,DC=dluhctest,DC=local"
    }
}
