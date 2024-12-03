@file:Suppress("FunctionNaming", "FunctionName", "FunctionParameterNaming", "LocalVariableName")

package tel.schich.pgcryptokt.hashing

import tel.schich.pgcryptokt.hashing.crypt.BLOWFISH_LEGACY_PREFIX
import tel.schich.pgcryptokt.hashing.crypt.BLOWFISH_PREFIX
import tel.schich.pgcryptokt.hashing.crypt.MD5_PREFIX
import tel.schich.pgcryptokt.hashing.crypt.XDES_PREFIX
import tel.schich.pgcryptokt.hashing.crypt.blowfish
import tel.schich.pgcryptokt.hashing.crypt.des
import tel.schich.pgcryptokt.hashing.crypt.generateBlowfishSalt
import tel.schich.pgcryptokt.hashing.crypt.generateDesSalt
import tel.schich.pgcryptokt.hashing.crypt.generateMd5Salt
import tel.schich.pgcryptokt.hashing.crypt.generateXdesSalt
import tel.schich.pgcryptokt.hashing.crypt.md5
import tel.schich.pgcryptokt.hashing.crypt.xdes
import tel.schich.pgcryptokt.threadLocalSecureRandom

val base64Alphabet = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz".toCharArray()

fun gen_salt(type: String, iter_count: Int? = null): String {
    return when (type) {
        "des" -> generateDesSalt(threadLocalSecureRandom.get())
        "xdes" -> generateXdesSalt(threadLocalSecureRandom.get(), iter_count)
        "md5" -> generateMd5Salt(threadLocalSecureRandom.get())
        "bf" -> generateBlowfishSalt(threadLocalSecureRandom.get(), iter_count)
        else -> throw IllegalArgumentException("Unknown crypt algorithm: $type")
    }
}

fun crypt(password: String, salt: String): String {
    return when {
        salt.startsWith(BLOWFISH_PREFIX) -> blowfish(password, salt.toCharArray())
        salt.startsWith(BLOWFISH_LEGACY_PREFIX) -> blowfish(password, salt.toCharArray())
        salt.startsWith("$2$") -> throw IllegalArgumentException("Illegal salt given: $salt")
        salt.startsWith(MD5_PREFIX) -> md5(password, salt)
        salt.startsWith(XDES_PREFIX) -> xdes(password, salt.toCharArray())
        else -> des(password, salt)
    }
}
