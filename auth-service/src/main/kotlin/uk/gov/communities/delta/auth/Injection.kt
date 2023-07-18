package uk.gov.communities.delta.auth

import uk.gov.communities.delta.auth.config.LDAPConfig
import uk.gov.communities.delta.auth.config.SAMLConfig
import uk.gov.communities.delta.auth.controllers.internal.GenerateSAMLTokenController
import uk.gov.communities.delta.auth.controllers.external.DeltaLoginController
import uk.gov.communities.delta.auth.controllers.internal.OAuthTokenController
import uk.gov.communities.delta.auth.saml.SAMLTokenService
import uk.gov.communities.delta.auth.security.ADLdapLoginServiceImpl
import uk.gov.communities.delta.auth.security.LdapAuthenticationService
import uk.gov.communities.delta.auth.services.AuthorizationCodeService

class Injection {
    companion object {

        private val authorizationCodeService = AuthorizationCodeService()

        private fun samlTokenService(): SAMLTokenService {
            val signingCredentials = SAMLConfig.getSAMLSigningCredentials()
            return SAMLTokenService(signingCredentials)
        }

        fun ldapServiceUserAuthenticationService(): LdapAuthenticationService {
            val ldapService = ADLdapLoginServiceImpl(
                ADLdapLoginServiceImpl.Configuration(
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

        fun externalDeltaLoginController(): DeltaLoginController {
            val ldapService = ADLdapLoginServiceImpl(
                ADLdapLoginServiceImpl.Configuration(
                    LDAPConfig.DELTA_LDAP_URL,
                    LDAPConfig.LDAP_DELTA_USER_DN_FORMAT,
                    LDAPConfig.LDAP_GROUP_DN_FORMAT
                )
            )
            return DeltaLoginController(ldapService, authorizationCodeService)
        }

        fun internalOAuthTokenController(): OAuthTokenController {
            return OAuthTokenController(authorizationCodeService)
        }
    }
}
