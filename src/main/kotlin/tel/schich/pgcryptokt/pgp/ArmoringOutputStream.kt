package tel.schich.pgcryptokt.pgp

import org.bouncycastle.bcpg.CRC24
import java.io.OutputStream

/**
 * This is a port of the PG code
 */
class ArmoringOutputStream(private val next: OutputStream, private val headers: List<Pair<String, String>>) : OutputStream() {
    private var headerWritten: Boolean = false
    private var bytesWritten: Int = 0
    private var crc24 = CRC24()
    private var buf = 0u
    private var pos = 2

    private fun writeBase64Char(index: UInt) {
        next.write(ALPHABET[index.toInt()].code)
        bytesWritten += 1
        if (bytesWritten == 76) {
            next.write(LF)
            bytesWritten = 0
        }
    }

    override fun write(byte: Int) {
        if (!headerWritten) {
            next.write(HEADER)
            for ((name, value) in headers) {
                next.write(name.toByteArray())
                next.write(HEADER_SEPARATOR)
                next.write(value.toByteArray())
                next.write(LF)
            }
            next.write(LF)
            headerWritten = true
        }

        crc24.update(byte)

        buf = buf or (byte.toUByte().toUInt() shl (pos shl 3))
        pos -= 1

        if (pos < 0) {
            writeBase64Char((buf shr 18) and 0b11_11_11u)
            writeBase64Char((buf shr 12) and 0b11_11_11u)
            writeBase64Char((buf shr 6) and 0b11_11_11u)
            writeBase64Char((buf) and 0b11_11_11u)

            pos = 2
            buf = 0u
        }
    }

    override fun flush() {
        if (pos != 2) {
            writeBase64Char((buf shr 18) and 0b11_11_11u)
            writeBase64Char((buf shr 12) and 0b11_11_11u)
            if (pos == 0) {
                writeBase64Char((buf shr 6) and 0b11_11_11u)
            } else {
                next.write(PAD_CHAR)
            }
            next.write(PAD_CHAR)

            pos = 2
        }
        next.flush()
    }

    override fun close() {
        flush()
        next.write(LF)
        next.write(PAD_CHAR)
        writeBase64Char((crc24.value.toUInt() shr 18) and 0b00_11_11_11u)
        writeBase64Char((crc24.value.toUInt() shr 12) and 0b00_11_11_11u)
        writeBase64Char((crc24.value.toUInt() shr 6) and 0b00_11_11_11u)
        writeBase64Char((crc24.value.toUInt()) and 0b00_11_11_11u)
        next.write(FOOTER)
        next.close()
    }

    private companion object {
        private const val LF = '\n'.code
        private const val ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
        private val HEADER = "-----BEGIN PGP MESSAGE-----\n".toByteArray()
        private val FOOTER = "\n-----END PGP MESSAGE-----\n".toByteArray()
        private val HEADER_SEPARATOR = ": ".toByteArray()
        private val PAD_CHAR = "=".toByteArray()
    }
}