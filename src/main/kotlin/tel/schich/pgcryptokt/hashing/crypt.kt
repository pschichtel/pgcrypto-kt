package tel.schich.pgcryptokt.hashing

import tel.schich.pgcryptokt.bytesToBase64
import tel.schich.pgcryptokt.calculateBase64Size
import tel.schich.pgcryptokt.threadLocalSecureRandom
import tel.schich.pgcryptokt.threeBytesFromIntToBase64
import java.security.SecureRandom

private val base64Alphabet = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz".toCharArray()

sealed interface CryptAlgorithm {
    fun genSalt(random: SecureRandom, iterationCount: Int?): String
    fun crypt(password: String, salt: String): String

    object DES : CryptAlgorithm {
        override fun genSalt(random: SecureRandom, iterationCount: Int?): String {
            val input = ByteArray(2)
            random.nextBytes(input)
            val salt = StringBuilder(2)
            salt.append(base64Alphabet[input[0].toUByte().toInt() and 0x3f])
            salt.append(base64Alphabet[input[1].toUByte().toInt() and 0x3f])
            return salt.toString()
        }

        override fun crypt(password: String, salt: String): String {
            TODO("DES not yet implemented")
        }
    }
    object XDES : CryptAlgorithm {
        const val prefix = "_"

        private const val minIterationCount: Int = 1
        private const val defaultIterationCount: Int = 725
        private const val maxIterationCount: Int = 16777215

        override fun genSalt(random: SecureRandom, iterationCount: Int?): String {
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
            threeBytesFromIntToBase64(salt, iterations, base64Alphabet)
            bytesToBase64(salt, input, 0, input.size, base64Alphabet)
            return salt.toString()
        }

        override fun crypt(password: String, salt: String): String {
            TODO("XDES not yet implemented")
        }
    }
    object MD5 : CryptAlgorithm {
        const val prefix = "$1$"

        override fun genSalt(random: SecureRandom, iterationCount: Int?): String {
            val input = ByteArray(6)
            random.nextBytes(input)
            val salt = StringBuilder(prefix.length + calculateBase64Size(input.size))
            salt.append(prefix)
            bytesToBase64(salt, input, 0, input.size, base64Alphabet)
            return salt.toString()
        }

        override fun crypt(password: String, salt: String): String {
            TODO("MD5 not yet implemented")
        }
    }
    object Blowfish : CryptAlgorithm {
        const val prefix = "$2a$"
        private const val minIterationCount: Int = 4
        private const val defaultIterationCount: Int = 6
        private const val maxIterationCount: Int = 31

        private val alphabet = "./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789".toCharArray()

        override fun genSalt(random: SecureRandom, iterationCount: Int?): String {
            val iterations = iterationCount ?: defaultIterationCount
            if (iterations < minIterationCount || iterations > maxIterationCount) {
                error("iterations count of $iterations is not within $minIterationCount and $maxIterationCount")
            }
            val input = ByteArray(16)
            random.nextBytes(input)
            val salt = StringBuilder(prefix.length + 3 + calculateBase64Size(input.size))
            salt.append('0' + iterations / 10)
            salt.append('0' + iterations % 10)
            salt.append('$')
            salt.append(prefix)
            bytesToBase64(salt, input, 0, input.size, alphabet)
            return salt.toString()
        }

        override fun crypt(password: String, salt: String): String {
            TODO("Blowflish not yet implemented")
        }
    }
}

private fun parseType(type: String): CryptAlgorithm = when (type) {
    "des" -> CryptAlgorithm.DES
    "xdes" -> CryptAlgorithm.XDES
    "md5" -> CryptAlgorithm.MD5
    "bf" -> CryptAlgorithm.Blowfish
    else -> throw IllegalArgumentException("Unknown crypt algorithm: $type")
}

fun gen_salt(type: String, iter_count: Int? = null): String {
    return parseType(type).genSalt(threadLocalSecureRandom.get(), iter_count)
}

fun crypt(password: String, salt: String): String {
    return when {
        salt.startsWith(CryptAlgorithm.Blowfish.prefix) || salt.startsWith("$2x$") -> CryptAlgorithm.Blowfish.crypt(password, salt)
        salt.startsWith("$2$") -> throw IllegalArgumentException("Illegal salt given: $salt")
        salt.startsWith(CryptAlgorithm.MD5.prefix) -> CryptAlgorithm.MD5.crypt(password, salt)
        salt.startsWith(CryptAlgorithm.XDES.prefix) -> CryptAlgorithm.XDES.crypt(password, salt)
        else -> CryptAlgorithm.DES.crypt(password, salt)
    }
}