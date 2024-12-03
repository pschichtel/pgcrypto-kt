package tel.schich.pgcryptokt.hashing.crypt

import org.apache.commons.codec.digest.Md5Crypt
import tel.schich.pgcryptokt.bytesToBase64
import tel.schich.pgcryptokt.calculateBase64Size
import tel.schich.pgcryptokt.hashing.base64Alphabet
import java.security.SecureRandom

internal const val MD5_PREFIX = "$1$"

internal fun generateMd5Salt(random: SecureRandom): String {
    val input = ByteArray(6)
    random.nextBytes(input)
    val salt = StringBuilder(MD5_PREFIX.length + calculateBase64Size(input.size))
    salt.append(MD5_PREFIX)
    bytesToBase64(salt, input, 0, input.size, base64Alphabet)
    return salt.toString()
}

internal fun md5(password: String, salt: String): String {
    return Md5Crypt.md5Crypt(password.toByteArray(Charsets.UTF_8), salt)
}
