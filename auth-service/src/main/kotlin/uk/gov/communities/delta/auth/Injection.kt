package uk.gov.communities.delta.auth

import uk.gov.communities.delta.auth.config.LDAPConfig
import uk.gov.communities.delta.auth.config.SAMLConfig
import uk.gov.communities.delta.auth.controllers.GenerateSAMLTokenController
import uk.gov.communities.delta.auth.controllers.PublicDeltaLoginController
import uk.gov.communities.delta.auth.saml.SAMLTokenService
import uk.gov.communities.delta.auth.security.ADLdapLoginService
import uk.gov.communities.delta.auth.security.LdapAuthenticationService

class Injection {
    companion object {
        private fun samlTokenService(): SAMLTokenService {
            val signingCredentials = SAMLConfig.getSAMLSigningCredentials()
            return SAMLTokenService(signingCredentials)
        }

        fun ldapServiceUserAuthenticationService(): LdapAuthenticationService {
            val ldapService = ADLdapLoginService(
                ADLdapLoginService.Configuration(
                    LDAPConfig.DELTA_LDAP_URL,
                    LDAPConfig.LDAP_SERVICE_USER_DN_FORMAT,
                    LDAPConfig.LDAP_GROUP_DN_FORMAT
                )
            )
            return LdapAuthenticationService(ldapService, LDAPConfig.SERVICE_USER_GROUP_CN)
        }

        fun generateSAMLTokenController(): GenerateSAMLTokenController {
            return GenerateSAMLTokenController(samlTokenService())
        }

        fun publicDeltaLoginController(): PublicDeltaLoginController {
            val ldapService = ADLdapLoginService(
                ADLdapLoginService.Configuration(
                    LDAPConfig.DELTA_LDAP_URL,
                    LDAPConfig.LDAP_DELTA_USER_DN_FORMAT,
                    LDAPConfig.LDAP_GROUP_DN_FORMAT
                )
            )
            return PublicDeltaLoginController(ldapService)
        }
    }
}
