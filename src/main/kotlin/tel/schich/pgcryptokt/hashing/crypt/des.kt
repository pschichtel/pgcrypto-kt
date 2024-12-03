package tel.schich.pgcryptokt.hashing.crypt

import org.apache.commons.codec.digest.UnixCrypt
import tel.schich.pgcryptokt.hashing.base64Alphabet
import java.security.SecureRandom

internal fun generateDesSalt(random: SecureRandom): String {
    val input = ByteArray(2)
    random.nextBytes(input)
    val salt = StringBuilder(2)
    salt.append(base64Alphabet[input[0].toUByte().toInt() and 0x3f])
    salt.append(base64Alphabet[input[1].toUByte().toInt() and 0x3f])
    return salt.toString()
}

internal fun des(password: String, salt: String): String {
    return UnixCrypt.crypt(password, salt)
}
