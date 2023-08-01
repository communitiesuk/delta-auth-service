package uk.gov.communities.delta.auth.config

import org.bouncycastle.asn1.ASN1Integer
import org.bouncycastle.asn1.ASN1Sequence
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.openssl.PEMParser
import org.bouncycastle.util.io.pem.PemObject
import org.opensaml.security.x509.BasicX509Credential
import org.slf4j.LoggerFactory
import org.springframework.core.io.ClassPathResource
import java.io.ByteArrayInputStream
import java.io.Reader
import java.io.StringReader
import java.nio.charset.StandardCharsets
import java.security.KeyFactory
import java.security.KeyPair
import java.security.PrivateKey
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.security.spec.RSAPrivateCrtKeySpec
import java.security.spec.RSAPublicKeySpec
import java.util.*


class SAMLConfig private constructor() {

    companion object {
        private val logger = LoggerFactory.getLogger(SAMLConfig::class.java)

        fun credentialsFromEnvironment(): BasicX509Credential {
            val cert =
                Env.getRequiredOrDevFallback("DELTA_SAML_CERTIFICATE") { resourceToString("/auth/dev-saml-certificate.pem") }
            val key =
                Env.getRequiredOrDevFallback("DELTA_SAML_PRIVATE_KEY") { resourceToString("/auth/dev-saml-private-key.pem") }

            return BasicX509Credential(certificate(cert), signingKey(key))
        }

        fun insecureHardcodedCredentials(): BasicX509Credential {
            logger.info("Reading insecure SAML signing credentials from hardcoded pem files")
            val cert = resourceToString("/auth/dev-saml-certificate.pem")
            val key = resourceToString("/auth/dev-saml-private-key.pem")

            return BasicX509Credential(certificate(cert), signingKey(key))
        }

        private fun certificate(pem: String): X509Certificate {
            val o = parsePEM(pem)
            if (o.type.equals("CERTIFICATE", ignoreCase = true)) {
                val cf = CertificateFactory.getInstance("X.509")
                return cf.generateCertificates(ByteArrayInputStream(o.content)).last() as X509Certificate
            } else {
                throw Exception("Unexpected PemObject type " + o.type + " when parsing SAML certificate, expected CERTIFICATE")
            }
        }

        private fun signingKey(pem: String): PrivateKey {
            val o = parsePEM(pem)
            if (!o.type.equals("RSA PRIVATE KEY", ignoreCase = true)) {
                throw Exception("Unexpected PemObject type " + o.type + " when parsing SAML certificate, expected RSA PRIVATE KEY")
            }

            val seq = ASN1Sequence.fromByteArray(o.content) as ASN1Sequence
            if (seq.size() != 9) {
                throw RuntimeException("Failed to parse PKCS1 private RSA key, expected 9 ASN1 elements, got " + seq.size())
            }
            val mod = seq.getObjectAt(1) as ASN1Integer
            val pubExp = seq.getObjectAt(2) as ASN1Integer
            val privExp = seq.getObjectAt(3) as ASN1Integer
            val p1 = seq.getObjectAt(4) as ASN1Integer
            val p2 = seq.getObjectAt(5) as ASN1Integer
            val exp1 = seq.getObjectAt(6) as ASN1Integer
            val exp2 = seq.getObjectAt(7) as ASN1Integer
            val crtCoef = seq.getObjectAt(8) as ASN1Integer
            val pubSpec = RSAPublicKeySpec(mod.value, pubExp.value)
            val privSpec = RSAPrivateCrtKeySpec(
                mod.value, pubExp.value,
                privExp.value, p1.value, p2.value, exp1.value, exp2.value,
                crtCoef.value
            )
            val fact = KeyFactory.getInstance("RSA", BouncyCastleProvider())
            return KeyPair(fact.generatePublic(pubSpec), fact.generatePrivate(privSpec)).private
        }

        private fun resourceToString(path: String): String {
            val inputStream = Objects.requireNonNull(ClassPathResource(path).inputStream)
            return inputStream.readAllBytes().toString(StandardCharsets.UTF_8)
        }

        private fun parsePEM(pem: String): PemObject {
            val r: Reader = StringReader(pem)
            val pp = PEMParser(r)
            return pp.readPemObject()
        }
    }
}

