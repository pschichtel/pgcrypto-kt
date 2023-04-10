package tel.schich.pgcryptokt.hashing

import at.favre.lib.crypto.bcrypt.BCrypt
import at.favre.lib.crypto.bcrypt.LongPasswordStrategies.truncate
import org.apache.commons.codec.digest.Md5Crypt
import tel.schich.pgcryptokt.base64ToBytes
import tel.schich.pgcryptokt.bytesToBase64
import tel.schich.pgcryptokt.calculateBase64Size
import tel.schich.pgcryptokt.read24BitIntFromBase64
import tel.schich.pgcryptokt.threadLocalSecureRandom
import tel.schich.pgcryptokt.write24BitIntToBase64
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.spec.SecretKeySpec

private val base64Alphabet = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz".toCharArray()


private fun des(password: ByteArray, salt: Int, count: Int): String {
    val algoName = "DESede"
    val cipher = Cipher.getInstance("$algoName/ECB/NoPadding")
    val keySpec = SecretKeySpec(password, algoName)
    cipher.init(Cipher.ENCRYPT_MODE, keySpec)
    val hash = cipher.doFinal(password)

    // TODO this is definitely wrong

    return StringBuilder()
        .also { bytesToBase64(it, hash, 0, hash.size, base64Alphabet) }
        .toString()
}

sealed interface CryptAlgorithm {
    object DES : CryptAlgorithm {
        fun genSalt(random: SecureRandom): String {
            val input = ByteArray(2)
            random.nextBytes(input)
            val salt = StringBuilder(2)
            salt.append(base64Alphabet[input[0].toUByte().toInt() and 0x3f])
            salt.append(base64Alphabet[input[1].toUByte().toInt() and 0x3f])
            return salt.toString()
        }

        fun crypt(password: String, saltChars: CharArray): String {
            val salt = (base64Alphabet.indexOf(saltChars[0]) shl 6) or base64Alphabet.indexOf(saltChars[1])
            val passwordBytes = password.toByteArray(Charsets.UTF_8)

            return des(passwordBytes, salt, count = 25)
        }
    }
    object XDES : CryptAlgorithm {
        const val prefix = "_"

        private const val minIterationCount: Int = 1
        private const val defaultIterationCount: Int = 725
        private const val maxIterationCount: Int = 16777215

        fun genSalt(random: SecureRandom, iterationCount: Int?): String {
            val iterations = iterationCount ?: defaultIterationCount
            if (iterations < minIterationCount || iterations > maxIterationCount) {
                error("iterations count of $iterations is not within $minIterationCount and $maxIterationCount")
            }
            if ((iterations and 1) == 0) {
                error("iterations count of $iterations is not odd")
            }

            val input = ByteArray(3)
            random.nextBytes(input)
            val salt = StringBuilder(prefix.length + 4 + calculateBase64Size(input.size))
            write24BitIntToBase64(salt, iterations, base64Alphabet)
            bytesToBase64(salt, input, 0, input.size, base64Alphabet)
            return salt.toString()
        }

        fun crypt(password: String, saltChars: CharArray): String {
            val iterations = read24BitIntFromBase64(saltChars, 1, base64Alphabet)
            val salt = read24BitIntFromBase64(saltChars, 5, base64Alphabet)
            val passwordBytes = password.toByteArray(Charsets.UTF_8)
            return des(passwordBytes, salt, iterations)
        }
    }
    object MD5 : CryptAlgorithm {
        const val prefix = "$1$"

        fun genSalt(random: SecureRandom): String {
            val input = ByteArray(6)
            random.nextBytes(input)
            val salt = StringBuilder(prefix.length + calculateBase64Size(input.size))
            salt.append(prefix)
            bytesToBase64(salt, input, 0, input.size, base64Alphabet)
            return salt.toString()
        }

        fun crypt(password: String, salt: String): String {
            return Md5Crypt.md5Crypt(password.toByteArray(Charsets.UTF_8), salt)
        }
    }
    object Blowfish : CryptAlgorithm {
        const val prefix = "$2a$"
        const val legacyPrefix = "$2x$"
        private const val minIterationCount: Int = 4
        private const val defaultIterationCount: Int = 6
        private const val maxIterationCount: Int = 31

        private val hasher = BCrypt.with(BCrypt.Version.VERSION_2A, truncate(BCrypt.Version.VERSION_2A))
        private val legacyHasher = BCrypt.with(BCrypt.Version.VERSION_2X, truncate(BCrypt.Version.VERSION_2X))

        private val alphabet = "./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789".toCharArray()

        fun genSalt(random: SecureRandom, iterationCount: Int?): String {
            val iterations = iterationCount ?: defaultIterationCount
            if (iterations < minIterationCount || iterations > maxIterationCount) {
                error("iterations count of $iterations is not within $minIterationCount and $maxIterationCount")
            }
            val input = ByteArray(16)
            random.nextBytes(input)
            val salt = StringBuilder(prefix.length + 3 + calculateBase64Size(input.size))
            salt.append(prefix)
            salt.append('0' + iterations / 10)
            salt.append('0' + iterations % 10)
            salt.append('$')
            bytesToBase64(salt, input, 0, input.size, alphabet)
            return salt.toString()
        }

        fun crypt(password: String, saltChars: CharArray): String {
            val hasher = when (saltChars[2]) {
                'a' -> hasher
                'x' -> legacyHasher
                else -> error("Unsupported salt '$saltChars' !")
            }
            val cost = saltChars[4].digitToInt() * 10 + saltChars[5].digitToInt()
            val saltBytes = base64ToBytes(saltChars, 7, saltChars.size - 7, alphabet)
            return String(hasher.hash(cost, saltBytes, password.toByteArray(Charsets.UTF_8)), Charsets.UTF_8)
        }
    }
}

fun gen_salt(type: String, iter_count: Int? = null): String {
    return when (type) {
        "des" -> CryptAlgorithm.DES.genSalt(threadLocalSecureRandom.get())
        "xdes" -> CryptAlgorithm.XDES.genSalt(threadLocalSecureRandom.get(), iter_count)
        "md5" -> CryptAlgorithm.MD5.genSalt(threadLocalSecureRandom.get())
        "bf" -> CryptAlgorithm.Blowfish.genSalt(threadLocalSecureRandom.get(), iter_count)
        else -> throw IllegalArgumentException("Unknown crypt algorithm: $type")
    }
}

fun crypt(password: String, salt: String): String {
    return when {
        salt.startsWith(CryptAlgorithm.Blowfish.prefix) -> CryptAlgorithm.Blowfish.crypt(password, salt.toCharArray())
        salt.startsWith(CryptAlgorithm.Blowfish.legacyPrefix) -> CryptAlgorithm.Blowfish.crypt(password, salt.toCharArray())
        salt.startsWith("$2$") -> throw IllegalArgumentException("Illegal salt given: $salt")
        salt.startsWith(CryptAlgorithm.MD5.prefix) -> CryptAlgorithm.MD5.crypt(password, salt)
        salt.startsWith(CryptAlgorithm.XDES.prefix) -> CryptAlgorithm.XDES.crypt(password, salt.toCharArray())
        else -> CryptAlgorithm.DES.crypt(password, salt.toCharArray())
    }
}