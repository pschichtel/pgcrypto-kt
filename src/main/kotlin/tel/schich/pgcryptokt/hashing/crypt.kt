package tel.schich.pgcryptokt.hashing

import tel.schich.pgcryptokt.threadLocalSecureRandom
import java.lang.StringBuilder
import java.security.SecureRandom

private const val cryptBase64Charset =
"./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

private fun randomBytes(random: SecureRandom, n: Int): ByteArray {
    val output = ByteArray(n)
    random.nextBytes(output)
    return output
}

private fun threeByteIntToString(v: Int): String {
    val c1 = cryptBase64Charset[v and 0x3f]
    val c2 = cryptBase64Charset[(v ushr 6) and 0x3f]
    val c3 = cryptBase64Charset[(v ushr 12) and 0x3f]
    val c4 = cryptBase64Charset[(v ushr 18) and 0x3f]
    return "$c1$c2$c3$c4"
}

private fun threeBytesFromInputToString(input: ByteArray, offset: Int): String {
    val v = input[offset].toUByte().toInt() or (input[offset + 1].toUByte().toInt() shl 8) or (input[offset + 2].toUByte().toInt() ushr 16)
    return threeByteIntToString(v)
}

private fun desCrypt(password: String, salt: String): String {
    TODO("(X)DES not implemented yet")
}

sealed interface CryptAlgorithm {
    fun genSalt(random: SecureRandom, iterationCount: Int?): String
    fun crypt(password: String, salt: String): String

    object XDES : CryptAlgorithm {
        private const val minIterationCount: Int = 1
        private const val defaultIterationCount: Int = 725
        private const val maxIterationCount: Int = 16777215

        override fun genSalt(random: SecureRandom, iterationCount: Int?): String {
            val iterations = iterationCount ?: defaultIterationCount
            if (iterations < minIterationCount || iterations > maxIterationCount || iterations and 1 == 1) {
                throw IllegalArgumentException("Illegal iteration count provided: $iterations")
            }

            val input = randomBytes(random, 3)
            return "_${threeByteIntToString(iterations)}${threeBytesFromInputToString(input, 0)}"
        }

        override fun crypt(password: String, salt: String): String {
            return desCrypt(password, salt)
        }
    }
    object DES : CryptAlgorithm {
        override fun genSalt(random: SecureRandom, iterationCount: Int?): String {
            val buffer = randomBytes(random, 2)
            fun toChar(i: Int): Char = cryptBase64Charset[(buffer[i].toUByte().toInt() and 0x3F)]
            return "${toChar(0)}${toChar(1)}"
        }

        override fun crypt(password: String, salt: String): String {
            return desCrypt(password, salt)
        }
    }
    object Blowfish : CryptAlgorithm {
        private const val minIterationCount: Int = 4
        private const val defaultIterationCount: Int = 6
        private const val maxIterationCount: Int = 31

        private const val blowfishBase64Alphabet = "./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"

        /**
         * This function is a straighjt port from the PG codebase's BF_encode function
         */
        private fun blowfishEncode(input: ByteArray, out: StringBuilder) {
            var i = 0
            var c1: Int
            var c2: Int
            do {
                c1 = input[i++].toUByte().toInt()
                out.append(blowfishBase64Alphabet[c1 ushr 2])
                c1 = (c1 and 0x03) shl 4
                if (i >= input.size) {
                    out.append(blowfishBase64Alphabet[c1])
                    break
                }

                c2 = input[i++].toUByte().toInt()
                c1 = c1 or (c2 ushr 4)
                out.append(blowfishBase64Alphabet[c1])
                c1 = (c2 and 0x0f) shl 2
                if (i >= input.size) {
                    out.append(blowfishBase64Alphabet[c1])
                    break
                }

                c2 = input[i++].toUByte().toInt()
                c1 = c1 or (c2 ushr 6)
                out.append(blowfishBase64Alphabet[c1])
                out.append(blowfishBase64Alphabet[c2 and 0x3f])
            } while (i < input.size)
        }

        override fun genSalt(random: SecureRandom, iterationCount: Int?): String {
            val iterations = iterationCount ?: defaultIterationCount
            if (iterations < minIterationCount || iterations > maxIterationCount) {
                throw IllegalArgumentException("Illegal iteration count provided: $iterations")
            }

            fun letterFromZero(offset: Int): Char {
                return ('0'.code + offset).toChar()
            }

            val out = StringBuilder("\$2a\$")
            out.append(letterFromZero(iterations / 10))
            out.append(letterFromZero(iterations % 10))

            val input = randomBytes(random, 16)
            blowfishEncode(input, out)

            return out.toString()
        }

        override fun crypt(password: String, salt: String): String {
            TODO("Blowflish not yet implemented")
        }
    }
    object MD5 : CryptAlgorithm {
        override fun genSalt(random: SecureRandom, iterationCount: Int?): String {
            val input = randomBytes(random, 6)

            return "$1$${threeBytesFromInputToString(input, 0)}${threeBytesFromInputToString(input, 3)}"
        }

        override fun crypt(password: String, salt: String): String {
            TODO("MD5 not yet implemented")
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
    when {
        salt.startsWith("$2a$") || salt.startsWith("$2x$") -> CryptAlgorithm.Blowfish.crypt(password, salt)
        salt.startsWith("$2$") -> throw IllegalArgumentException("Illegal salt given: $salt")
        salt.startsWith("$1$") -> CryptAlgorithm.MD5.crypt(password, salt)
        salt.startsWith("_") -> CryptAlgorithm.XDES.crypt(password, salt)
        else -> CryptAlgorithm.DES.crypt(password, salt)
    }
    return salt
}