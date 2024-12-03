package tel.schich.pgcryptokt.hashing

import java.nio.charset.Charset
import java.security.MessageDigest

fun digest(data: String, type: String, charset: Charset = Charsets.UTF_8): ByteArray {
    return digest(data.toByteArray(charset), type)
}

fun digest(data: ByteArray, type: String): ByteArray {
    return MessageDigest.getInstance(mapHashAlgorithmName(type)).digest(data)
}
