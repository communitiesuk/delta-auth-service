package uk.gov.communities.delta.utils

import org.junit.Test
import uk.gov.communities.delta.auth.utils.toActiveDirectoryGUIDString
import uk.gov.communities.delta.auth.utils.toUUID
import kotlin.test.assertEquals


class UUIDUtilsTest {

    @Test
    fun testUUIDToString() {
        val hex = "01078E38BA10DB4488967F28F9837210"
        val bytes = hex.chunked(2)
            .map { it.toInt(16).toByte() }
            .toByteArray()
        val uuid = bytes.toUUID()

        assertEquals("01078e38-ba10-db44-8896-7f28f9837210", uuid.toString());
        assertEquals("388e0701-10ba-44db-8896-7f28f9837210", uuid.toActiveDirectoryGUIDString())
    }
}
