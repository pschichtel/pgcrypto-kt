package tel.schich.pgcryptokt.hashing

import tel.schich.pgcryptokt.threadLocalSecureRandom
import java.security.SecureRandom

sealed interface CryptAlgorithm {
    fun genSalt(random: SecureRandom, iterationCount: Int?): String
    fun crypt(password: String, salt: String): String

    object XDES : CryptAlgorithm {
        private const val minIterationCount: Int = 1
        private const val defaultIterationCount: Int = 725
        private const val maxIterationCount: Int = 16777215

        override fun genSalt(random: SecureRandom, iterationCount: Int?): String {
            TODO("XDES not yet implemented")
        }

        override fun crypt(password: String, salt: String): String {
            TODO("XDES not yet implemented")
        }
    }
    object DES : CryptAlgorithm {
        override fun genSalt(random: SecureRandom, iterationCount: Int?): String {
            TODO("DES not yet implemented")
        }

        override fun crypt(password: String, salt: String): String {
            TODO("DES not yet implemented")
        }
    }
    object Blowfish : CryptAlgorithm {
        private const val minIterationCount: Int = 4
        private const val defaultIterationCount: Int = 6
        private const val maxIterationCount: Int = 31

        override fun genSalt(random: SecureRandom, iterationCount: Int?): String {
            TODO("Blowflish not yet implemented")
        }

        override fun crypt(password: String, salt: String): String {
            TODO("Blowflish not yet implemented")
        }
    }
    object MD5 : CryptAlgorithm {
        override fun genSalt(random: SecureRandom, iterationCount: Int?): String {
            TODO("MD5 not yet implemented")
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
    return when {
        salt.startsWith("$2a$") || salt.startsWith("$2x$") -> CryptAlgorithm.Blowfish.crypt(password, salt)
        salt.startsWith("$2$") -> throw IllegalArgumentException("Illegal salt given: $salt")
        salt.startsWith("$1$") -> CryptAlgorithm.MD5.crypt(password, salt)
        salt.startsWith("_") -> CryptAlgorithm.XDES.crypt(password, salt)
        else -> CryptAlgorithm.DES.crypt(password, salt)
    }
}