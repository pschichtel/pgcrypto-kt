package tel.schich.pgcryptokt.hashing.crypt

import at.favre.lib.crypto.bcrypt.BCrypt
import at.favre.lib.crypto.bcrypt.LongPasswordStrategies
import tel.schich.pgcryptokt.base64ToBytes
import tel.schich.pgcryptokt.bytesToBase64
import tel.schich.pgcryptokt.calculateBase64Size
import java.security.SecureRandom

internal const val BLOWFISH_PREFIX = "$2a$"
internal const val BLOWFISH_LEGACY_PREFIX = "$2x$"
private const val minIterationCount: Int = 4
private const val defaultIterationCount: Int = 6
private const val maxIterationCount: Int = 31

private val hasher = BCrypt.with(BCrypt.Version.VERSION_2A, LongPasswordStrategies.truncate(BCrypt.Version.VERSION_2A))
private val legacyHasher = BCrypt.with(
    BCrypt.Version.VERSION_2X,
    LongPasswordStrategies.truncate(BCrypt.Version.VERSION_2X)
)

private val alphabet = "./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789".toCharArray()

internal fun generateBlowfishSalt(random: SecureRandom, iterationCount: Int?): String {
    val iterations = iterationCount ?: defaultIterationCount
    if (iterations < minIterationCount || iterations > maxIterationCount) {
        error("iterations count of $iterations is not within $minIterationCount and $maxIterationCount")
    }
    val input = ByteArray(16)
    random.nextBytes(input)
    val salt = StringBuilder(BLOWFISH_PREFIX.length + 3 + calculateBase64Size(input.size))
    salt.append(BLOWFISH_PREFIX)
    salt.append('0' + iterations / 10)
    salt.append('0' + iterations % 10)
    salt.append('$')
    bytesToBase64(salt, input, 0, input.size, alphabet)
    return salt.toString()
}

internal fun blowfish(password: String, saltChars: CharArray): String {
    val hasher = when (saltChars[2]) {
        'a' -> hasher
        'x' -> legacyHasher
        else -> error("Unsupported salt '$saltChars' !")
    }
    val cost = saltChars[4].digitToInt() * 10 + saltChars[5].digitToInt()
    val saltBytes = base64ToBytes(saltChars, 7, saltChars.size - 7, alphabet)
    return String(hasher.hash(cost, saltBytes, password.toByteArray(Charsets.UTF_8)), Charsets.UTF_8)
}