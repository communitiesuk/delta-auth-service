package uk.gov.communities.delta.auth.saml

import org.opensaml.saml.saml2.core.Assertion
import org.opensaml.saml.saml2.core.impl.AssertionMarshaller
import org.opensaml.security.credential.Credential
import org.opensaml.xmlsec.signature.Signature
import org.opensaml.xmlsec.signature.impl.SignatureBuilder
import org.opensaml.xmlsec.signature.support.SignatureConstants
import org.opensaml.xmlsec.signature.support.Signer


class SAMLAssertionSigner(private val signingCredential: Credential) {
    fun signAssertion(assertion: Assertion): Assertion {
        val builder = SignatureBuilder()
        val signature: Signature = builder.buildObject()
        signature.signingCredential = signingCredential
        signature.signatureAlgorithm = SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA256
        signature.canonicalizationAlgorithm = SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS
        assertion.signature = signature
        addXmlSignatureInstanceToAssertion(assertion)
        Signer.signObject(signature)
        return assertion
    }

    private fun addXmlSignatureInstanceToAssertion(assertion: Assertion) {
        val marshaller = AssertionMarshaller()
        marshaller.marshall(assertion)
    }
}

