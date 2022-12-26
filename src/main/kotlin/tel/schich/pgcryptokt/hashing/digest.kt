package tel.schich.pgcryptokt.hashing

import java.nio.charset.Charset
import java.security.MessageDigest

fun digest(data: String, type: String, charset: Charset = Charsets.UTF_8): ByteArray {
    return digest(data.toByteArray(charset), type)
}

fun digest(data: ByteArray, type: String): ByteArray {
    val mappedType = when (type) {
        "sha224" -> "sha-224"
        "sha256" -> "sha-256"
        "sha384" -> "sha-384"
        "sha512" -> "sha-512"
        else -> type
    }
    val messageDigest = MessageDigest.getInstance(mappedType)
    return messageDigest.digest(data)
}