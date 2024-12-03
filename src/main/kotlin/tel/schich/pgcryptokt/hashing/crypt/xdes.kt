package tel.schich.pgcryptokt.hashing.crypt

import tel.schich.pgcryptokt.bytesToBase64
import tel.schich.pgcryptokt.calculateBase64Size
import tel.schich.pgcryptokt.hashing.base64Alphabet
import tel.schich.pgcryptokt.write24BitIntToBase64
import java.security.SecureRandom

internal const val XDES_PREFIX = "_"

private const val MIN_ITERATION_COUNT: Int = 1
private const val DEFAULT_ITERATION_COUNT: Int = 725
private const val MAX_ITERATION_COUNT: Int = 16777215

internal fun generateXdesSalt(random: SecureRandom, iterationCount: Int?): String {
    val iterations = iterationCount ?: DEFAULT_ITERATION_COUNT
    if (iterations < MIN_ITERATION_COUNT || iterations > MAX_ITERATION_COUNT) {
        error("iterations count of $iterations is not within $MIN_ITERATION_COUNT and $MAX_ITERATION_COUNT")
    }
    if ((iterations and 1) == 0) {
        error("iterations count of $iterations is not odd")
    }

    val input = ByteArray(3)
    random.nextBytes(input)
    val salt = StringBuilder(XDES_PREFIX.length + 4 + calculateBase64Size(input.size))
    write24BitIntToBase64(salt, iterations, base64Alphabet)
    bytesToBase64(salt, input, 0, input.size, base64Alphabet)
    return salt.toString()
}

/**
 * Also called:
 * * bsdicrypt
 * * extended DES
 */
@Suppress("UNUSED_PARAMETER")
internal fun xdes(password: String, saltChars: CharArray): String {
    TODO("XDES is not implemented and not recommended, but PRs are welcome if you need this!")
}
