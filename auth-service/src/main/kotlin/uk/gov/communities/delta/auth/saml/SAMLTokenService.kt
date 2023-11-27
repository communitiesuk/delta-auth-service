package uk.gov.communities.delta.auth.saml

import org.opensaml.core.config.InitializationService
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport
import org.opensaml.core.xml.schema.XSString
import org.opensaml.core.xml.schema.impl.XSStringBuilder
import org.opensaml.saml.common.SAMLVersion
import org.opensaml.saml.common.xml.SAMLConstants
import org.opensaml.saml.saml2.core.*
import org.opensaml.saml.saml2.core.impl.*
import org.opensaml.security.x509.BasicX509Credential
import org.slf4j.LoggerFactory
import uk.gov.communities.delta.auth.repositories.LdapUser
import uk.gov.communities.delta.auth.utils.timed
import java.io.StringWriter
import java.nio.charset.StandardCharsets
import java.time.Instant
import java.util.*
import java.util.concurrent.atomic.AtomicBoolean
import javax.xml.namespace.QName
import javax.xml.transform.OutputKeys
import javax.xml.transform.TransformerFactory
import javax.xml.transform.dom.DOMSource
import javax.xml.transform.stream.StreamResult


class SAMLTokenService {
    private val logger = LoggerFactory.getLogger(this.javaClass)

    fun generate(credential: BasicX509Credential, user: LdapUser, validFrom: Instant, validTo: Instant) =
        logger.timed("Generate SAML token") {
            if (!initialised.get()) {
                // Lazily initialise the OpenSAML library as it takes a second or so to start
                initialiseOpenSaml()
            }
            try {
                val roles = user.memberOfCNs.filter { it.startsWith("datamart-delta-") }
                val assertion = makeAssertionElement(user.cn, roles, validFrom, validTo)

                // This block of code reportedly comes from MarkLogic support, though we no longer have access to the original ticket
                // Build a SAML Response and add required information
                val response = ResponseBuilder().buildObject()
                response.version = SAMLVersion.VERSION_20
                // * Issue Timestamp (Use same value from Assertion)
                response.issueInstant = assertion.issueInstant
                // * Status Code SUCCESS
                val stat = StatusBuilder().buildObject()
                val statCode = StatusCodeBuilder().buildObject()
                statCode.value = "urn:oasis:names:tc:SAML:2.0:status:Success"
                stat.statusCode = statCode
                response.status = stat
                // * ID (Any Random GUID but must be different from Assertion ID)
                response.id = assertion.id + "-1"
                // * Sign the assertion with our self-signed key and certificate
                val signedAssertion = SAMLAssertionSigner(credential).signAssertion(assertion)
                response.assertions.add(signedAssertion)
                // End build SAML response
                val token = marshalToString(response)
                val encodedToken = base64Encode(token)
                encodedToken
            } catch (ex: Exception) {
                throw RuntimeException("Failed to generate SAML token", ex)
            }
        }

    private fun base64Encode(s: String): String {
        val bytes = s.toByteArray(StandardCharsets.UTF_8)
        return String(Base64.getEncoder().encode(bytes), StandardCharsets.UTF_8)
    }

    /*
     * This part of the token was originally generated using Keycloak's Token Exchange feature,
     * however this has been removed in favour of constructing it ourselves here to avoid a round trip.
     * Wrapping the Assertion in a Response element was always done in the API, see above.
     *
     * The functions below are therefore built to mimic the structure Keycloak generates as we know that works with MarkLogic.
     *
     * We end up with a fairly standard SAML response, similar to e.g. https://www.samltool.com/generic_sso_res.php
     */
    private fun makeAssertionElement(
        username: String,
        roles: List<String>,
        validFrom: Instant,
        validTo: Instant,
    ): Assertion {
        val assertion =
            AssertionBuilder().buildObject(SAMLConstants.SAML20_NS, Assertion.DEFAULT_ELEMENT_LOCAL_NAME, "saml")
        assertion.id = "ID_" + UUID.randomUUID()
        assertion.issueInstant = validFrom
        assertion.issuer = makeIssuerElement()
        assertion.subject = makeSubjectElement(username)
        assertion.conditions = makeConditionsElement(validFrom, validTo)
        assertion.attributeStatements.add(makeAttributeStatementElement(roles))
        return assertion
    }

    private fun makeSubjectElement(username: String): Subject {
        val subject = SubjectBuilder().buildObject(SAMLConstants.SAML20_NS, Subject.DEFAULT_ELEMENT_LOCAL_NAME, "saml")
        val nameId = NameIDBuilder().buildObject(SAMLConstants.SAML20_NS, NameID.DEFAULT_ELEMENT_LOCAL_NAME, "saml")
        nameId.value = username
        nameId.format = "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"
        subject.nameID = nameId
        return subject
    }

    private fun makeConditionsElement(validFrom: Instant, validTo: Instant): Conditions {
        val audience =
            AudienceBuilder().buildObject(SAMLConstants.SAML20_NS, Audience.DEFAULT_ELEMENT_LOCAL_NAME, "saml")
        audience.uri = "api-ml-saml"
        val audienceRestriction = AudienceRestrictionBuilder().buildObject(
            SAMLConstants.SAML20_NS,
            AudienceRestriction.DEFAULT_ELEMENT_LOCAL_NAME,
            "saml"
        )
        audienceRestriction.audiences.add(audience)
        val conditions =
            ConditionsBuilder().buildObject(SAMLConstants.SAML20_NS, Conditions.DEFAULT_ELEMENT_LOCAL_NAME, "saml")
        conditions.notBefore = validFrom
        conditions.notOnOrAfter = validTo
        conditions.conditions.add(audienceRestriction)
        return conditions
    }

    private fun makeAttributeStatementElement(userRoles: List<String>): AttributeStatement {
        val attribute =
            AttributeBuilder().buildObject(SAMLConstants.SAML20_NS, Attribute.DEFAULT_ELEMENT_LOCAL_NAME, "saml")
        attribute.name = "Role"
        attribute.nameFormat = "urn:oasis:names:tc:SAML:2.0:attrname-format:basic"
        val attributeValues = attribute.attributeValues
        for (role in userRoles) {
            val stringBuilder = XSStringBuilder()
            val stringValue = stringBuilder.buildObject(
                QName(SAMLConstants.SAML20_NS, AttributeValue.DEFAULT_ELEMENT_NAME.localPart, "saml"),
                XSString.TYPE_NAME
            )
            stringValue.value = role
            attributeValues.add(stringValue)
        }
        val attributeStatement = AttributeStatementBuilder().buildObject(
            SAMLConstants.SAML20_NS,
            AttributeStatement.DEFAULT_ELEMENT_LOCAL_NAME,
            "saml"
        )
        attributeStatement.attributes.add(attribute)
        return attributeStatement
    }

    private fun makeIssuerElement(): Issuer {
        val issuer = IssuerBuilder().buildObject(SAMLConstants.SAML20_NS, Issuer.DEFAULT_ELEMENT_LOCAL_NAME, "saml")
        issuer.value = "api-ml-saml"
        return issuer
    }

    private fun marshalToString(response: Response): String {
        // Marshal Response to a Document Element
        val rMarsh = ResponseMarshaller()
        val plain = rMarsh.marshall(response)

        // Transform Response Element to an XML String
        val transFactory = TransformerFactory.newInstance()
        val transformer = transFactory.newTransformer()
        val buffer = StringWriter()
        transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes")
        transformer.transform(DOMSource(plain), StreamResult(buffer))
        return buffer.toString()
    }

    private fun initialiseOpenSaml() {
        synchronized(SAMLTokenService::class.java) {
            if (!initialised.get()) {
                logger.info("Initialising OpenSAML library")
                InitializationService.initialize()
                logger.debug("OpenSAML has " + XMLObjectProviderRegistrySupport.getMarshallerFactory().marshallers.size + " marshallers loaded")
                initialised.set(true)
            }
        }
    }

    companion object {
        private val initialised = AtomicBoolean(false)
    }
}
