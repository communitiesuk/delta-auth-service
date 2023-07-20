package uk.gov.communities.delta.auth.services

import java.security.MessageDigest
import java.security.SecureRandom
import kotlin.io.encoding.Base64
import kotlin.io.encoding.ExperimentalEncodingApi

private val sr: SecureRandom by lazy { SecureRandom() }
private val md = MessageDigest.getInstance("SHA3-256")

@OptIn(ExperimentalEncodingApi::class)
fun randomBase64(length: Int): String {
    val bytes = ByteArray(length)
    sr.nextBytes(bytes)
    return Base64.UrlSafe.encode(bytes)
}

@OptIn(ExperimentalEncodingApi::class)
fun hashBase64String(str: String): ByteArray {
    val bytes = Base64.UrlSafe.decode(str)
    return md.digest(bytes)
}
