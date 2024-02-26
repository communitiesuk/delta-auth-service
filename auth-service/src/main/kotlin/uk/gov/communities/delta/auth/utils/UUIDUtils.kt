package uk.gov.communities.delta.auth.utils

import java.nio.ByteBuffer
import java.util.*

// Microsoft use a mixed-endian text representation of GUIDs.
// https://en.wikipedia.org/wiki/Universally_unique_identifier#Encoding
// > For example, 00112233-4455-6677-8899-aabbccddeeff is encoded as the bytes 33 22 11 00 55 44 77 66 88 99 aa bb cc dd ee ff.[19][20]
@OptIn(ExperimentalStdlibApi::class)
fun ByteArray.toActiveDirectoryGUIDString(): String {
    if (size != 16) {
        throw IllegalArgumentException("GUID must be 16 bytes")
    }
    val bytes = ByteBuffer.wrap(this)

    val byteOrder = listOf(3, 2, 1, 0, -1, 5, 4, -1, 7, 6, -1, 8, 9, -1, 10, 11, 12, 13, 14, 15)
    val sb = StringBuilder(36)
    for (b in byteOrder) {
        sb.append(
            if (b == -1) '-'
            else bytes[b].toHexString()
        )
    }
    return sb.toString()
}
