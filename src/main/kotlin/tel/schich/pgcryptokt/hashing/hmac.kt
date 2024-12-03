package tel.schich.pgcryptokt.hashing

import java.nio.charset.Charset
import java.security.MessageDigest
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

fun hmac(data: String, key: String, type: String, charset: Charset = Charsets.UTF_8): ByteArray {
    return hmac(data.toByteArray(charset), key.toByteArray(charset), type)
}

fun hmac(data: ByteArray, key: ByteArray, type: String): ByteArray {
    val algorithm = "hmac$type"
    val mac = Mac.getInstance(algorithm)
    val secretKey = if (key.size > mac.macLength) {
        SecretKeySpec(MessageDigest.getInstance(mapHashAlgorithmName(type)).digest(key), algorithm)
    } else {
        SecretKeySpec(key, algorithm)
    }
    mac.init(secretKey)
    return mac.doFinal(data)
}
