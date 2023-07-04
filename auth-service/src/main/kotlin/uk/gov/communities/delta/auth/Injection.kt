package uk.gov.communities.delta.auth

import uk.gov.communities.delta.auth.config.SAMLConfig
import uk.gov.communities.delta.auth.controllers.GenerateSAMLTokenController
import uk.gov.communities.delta.auth.saml.SAMLTokenService
import uk.gov.communities.delta.auth.security.DeltaADLdapAuthentication

class Injection {
    companion object {
        private fun samlTokenService(): SAMLTokenService {
            val signingCredentials = SAMLConfig.getSAMLSigningCredentials()
            return SAMLTokenService(signingCredentials)
        }

        fun deltaADLdapAuthentication(): DeltaADLdapAuthentication {
            return DeltaADLdapAuthentication()
        }

        fun generateSAMLTokenController(): GenerateSAMLTokenController {
            return GenerateSAMLTokenController(samlTokenService())
        }
    }
}
