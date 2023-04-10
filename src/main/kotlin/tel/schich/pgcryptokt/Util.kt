package tel.schich.pgcryptokt

import java.io.ByteArrayOutputStream
import java.security.SecureRandom
import kotlin.math.ceil

internal val threadLocalSecureRandom = ThreadLocal.withInitial { SecureRandom() }

internal fun threeBytesFromIntToBase64(output: StringBuilder, value: Int, alphabet: CharArray) {
    output.append(alphabet[value and 0x3f])
    output.append(alphabet[(value shr 6) and 0x3f])
    output.append(alphabet[(value shr 12) and 0x3f])
    output.append(alphabet[(value shr 18) and 0x3f])
}

/**
 * This is a port of the PG's BF_encode.
 * While it sounds like a Blowfish-specific encoding, it's really just a padding-free base64 encoder with a custom
 * alphabet.
 */
internal fun bytesToBase64(output: StringBuilder, input: ByteArray, offset: Int, length: Int, alphabet: CharArray) {
    var i = 0
    var c1: Int
    var c2: Int
    while (i < length) {
        c1 = input[offset + i++].toUByte().toInt()
        output.append(alphabet[c1 shr 2])
        c1 = (c1 and 0b11) shl 4
        if (i >= length) {
            output.append(alphabet[c1])
            break
        }

        c2 = input[offset + i++].toUByte().toInt()
        c1 = c1 or (c2 shr 4)
        output.append(alphabet[c1])
        c1 = (c2 and 0b1111) shl 2
        if (i >= length) {
            output.append(alphabet[c1])
            break
        }

        c2 = input[offset + i++].toUByte().toInt()
        output.append(alphabet[c1 or (c2 shr 6)])
        output.append(alphabet[c2 and 0b111111])
    }
}

internal fun calculateBase64Size(bytes: Int): Int = ceil((bytes * 8) / 6.0).toInt()

fun base64ToBytes(input: CharArray, offset: Int, length: Int, alphabet: CharArray): ByteArray {
    fun lookupValue(char: Char): Int {
        val value = alphabet.indexOf(char)
        if (value == -1) {
            error("Character $char is not in alphabet: $alphabet")
        }
        return value
    }

    val outputSize = calculateByteSize(length)
    val output = ByteArrayOutputStream(outputSize)

    var i = 0
    var c1: Int
    var c2: Int
    while (i < length && output.size() < outputSize) {
        c1 = lookupValue(input[offset + i++])
        if (i >= length) {
            break
        }
        c2 = lookupValue(input[offset + i++])
        output.write((c1 shl 2) or (c2 shr 4))
        c1 = c2 and 0b1111
        if (i >= length || output.size() >= outputSize) {
            break
        }
        c2 = lookupValue(input[offset + i++])
        output.write((c1 shl 4) or (c2 shr 2))
        c1 = c2 and 0b11
        if (i >= length || output.size() >= outputSize) {
            break
        }
        c2 = lookupValue(input[offset + i++])
        output.write((c1 shl 6) or c2)
    }

    return output.toByteArray()
}

internal fun calculateByteSize(base64Chars: Int): Int = (base64Chars * 6) / 8
