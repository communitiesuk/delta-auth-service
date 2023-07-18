package uk.gov.communities.delta.auth

import uk.gov.communities.delta.auth.config.LDAPConfig
import uk.gov.communities.delta.auth.config.SAMLConfig
import uk.gov.communities.delta.auth.controllers.external.DeltaLoginController
import uk.gov.communities.delta.auth.controllers.internal.GenerateSAMLTokenController
import uk.gov.communities.delta.auth.controllers.internal.OAuthTokenController
import uk.gov.communities.delta.auth.saml.SAMLTokenService
import uk.gov.communities.delta.auth.security.ADLdapLoginService
import uk.gov.communities.delta.auth.security.LdapAuthenticationService
import uk.gov.communities.delta.auth.services.AuthorizationCodeService
import uk.gov.communities.delta.auth.services.LdapService
import uk.gov.communities.delta.auth.services.UserLookupService

class Injection {
    companion object {
        private val authorizationCodeService = AuthorizationCodeService()
        private val samlTokenService = SAMLTokenService(SAMLConfig.getSAMLSigningCredentials())
        private val ldapService = LdapService(
            LdapService.Configuration(
                ldapUrl = LDAPConfig.DELTA_LDAP_URL,
                groupDnFormat = LDAPConfig.LDAP_GROUP_DN_FORMAT
            )
        )
        private val userLookupService = UserLookupService(
            UserLookupService.Configuration(
                LDAPConfig.LDAP_DELTA_USER_DN_FORMAT,
                LDAPConfig.ldapAuthServiceUserDn,
                LDAPConfig.LDAP_AUTH_SERVICE_USER_PASSWORD,
            ),
            ldapService
        )

        fun ldapServiceUserAuthenticationService(): LdapAuthenticationService {
            val adLoginService = ADLdapLoginService(
                ADLdapLoginService.Configuration(LDAPConfig.LDAP_SERVICE_USER_DN_FORMAT),
                ldapService
            )
            return LdapAuthenticationService(adLoginService, LDAPConfig.SERVICE_USER_GROUP_CN)
        }

        fun generateSAMLTokenController() = GenerateSAMLTokenController(samlTokenService)

        fun externalDeltaLoginController(): DeltaLoginController {
            val adLoginService = ADLdapLoginService(
                ADLdapLoginService.Configuration(LDAPConfig.LDAP_DELTA_USER_DN_FORMAT),
                ldapService
            )
            return DeltaLoginController(adLoginService, authorizationCodeService)
        }

        fun internalOAuthTokenController() = OAuthTokenController(
            authorizationCodeService,
            userLookupService,
            samlTokenService,
        )
    }
}
