package tel.schich.pgcryptokt

import org.junit.jupiter.api.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals


class UtilTests {
    private val alphabet = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz".toCharArray()

    @Test
    fun encode4BytesToBase64() {
        val input = byteArrayOf(255.toByte(), 0.toByte(), 127.toByte(), 128.toByte())
        val base64 = StringBuilder().also { bytesToBase64(it, input, 0, input.size, alphabet) }.toString()

        assertEquals("zk/zU.", base64)
    }

    @Test
    fun encode3BytesToBase64() {
        val input = byteArrayOf(255.toByte(), 0.toByte(), 127.toByte())
        val base64 = StringBuilder().also { bytesToBase64(it, input, 0, input.size, alphabet) }.toString()

        assertEquals("zk/z", base64)
    }

    @Test
    fun encode4BytesRoundTrip() {
        val input = byteArrayOf(255.toByte(), 0.toByte(), 127.toByte(), 128.toByte())
        val base64 = StringBuilder().also { bytesToBase64(it, input, 0, input.size, alphabet) }.toString()
        val decoded = base64ToBytes(base64.toCharArray(), 0, base64.length, alphabet)

        assertContentEquals(input, decoded)
    }

    @Test
    fun encode3BytesRoundTrip() {
        val input = byteArrayOf(255.toByte(), 0.toByte(), 127.toByte())
        val base64 = StringBuilder().also { bytesToBase64(it, input, 0, input.size, alphabet) }.toString()
        val decoded = base64ToBytes(base64.toCharArray(), 0, base64.length, alphabet)

        assertContentEquals(input, decoded)
    }
}