package uk.gov.communities.delta.utils

import org.junit.Test
import uk.gov.communities.delta.auth.utils.toGUIDString
import kotlin.test.assertEquals


class UUIDUtilsTest {

    @Test
    fun testUUIDToString() {
        val hex = "01078E38BA10DB4488967F28F9837210"
        val bytes = hex.chunked(2)
            .map { it.toInt(16).toByte() }
            .toByteArray()

        assertEquals("388e0701-10ba-44db-8896-7f28f9837210", bytes.toGUIDString())
    }
}
