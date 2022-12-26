package tel.schich.pgcryptokt

import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

enum class Algorithm {
    BF,
    AES,
}

enum class AlgorithmMode {
    CBC,
    ECB,
}

enum class AlgorithmPadding {
    PKCS,
    NONE,
}

data class AlgorithmType(val algorithm: Algorithm, val mode: AlgorithmMode, val padding: AlgorithmPadding)

private fun parseAlgorithm(s: String) = when (s) {
    "bf" -> Algorithm.BF
    "aes" -> Algorithm.AES
    else -> throw IllegalArgumentException("Unknown algorithm '$s'!")
}

private fun parseMode(s: String) = when (s) {
    "cbc" -> AlgorithmMode.CBC
    "ecb" -> AlgorithmMode.ECB
    else -> throw IllegalArgumentException("Unknown mode '$s'!")
}

private fun parsePadding(s: String) = when (s) {
    "pkcs" -> AlgorithmPadding.PKCS
    "none" -> AlgorithmPadding.NONE
    else -> throw IllegalArgumentException("Unknown padding '$s'!")
}

private const val PADDING_SEPARATOR = "/pad:"

private fun parseType(s: String): AlgorithmType {
    val dashIndex = s.indexOf('-')
    val paddingSeparatorIndex = s.indexOf(PADDING_SEPARATOR)
    return when {
        dashIndex != -1 && paddingSeparatorIndex != -1 -> AlgorithmType(parseAlgorithm(s.substring(0, dashIndex)), parseMode(s.substring(dashIndex + 1, paddingSeparatorIndex)), parsePadding(s.substring(paddingSeparatorIndex + PADDING_SEPARATOR.length)))
        dashIndex != -1 -> AlgorithmType(parseAlgorithm(s.substring(0, dashIndex)), parseMode(s.substring(dashIndex + 1)), padding = AlgorithmPadding.PKCS)
        paddingSeparatorIndex != -1 -> AlgorithmType(parseAlgorithm(s.substring(0, paddingSeparatorIndex)), mode = AlgorithmMode.CBC, parsePadding(s.substring(paddingSeparatorIndex + PADDING_SEPARATOR.length)))
        else -> AlgorithmType(parseAlgorithm(s), mode = AlgorithmMode.CBC, padding = AlgorithmPadding.PKCS)
    }
}

private fun processWithIv(data: ByteArray?, key: ByteArray?, iv: ByteArray?, type: String?, encrypt: Boolean): ByteArray? {
    if (data == null || key == null || type == null) {
        return null
    }

    val (algo, mode, padding) = parseType(type)
    val algoName = when (algo) {
        Algorithm.BF -> "Blowfish"
        Algorithm.AES -> "AES"
    }
    val modeName = when (mode) {
        AlgorithmMode.CBC -> "CBC"
        AlgorithmMode.ECB -> "ECB"
    }
    val paddingName = when (padding) {
        AlgorithmPadding.PKCS -> "PKCS5Padding"
        AlgorithmPadding.NONE -> "NoPadding"
    }
    val cipher = Cipher.getInstance("$algoName/$modeName/$paddingName")
    val cipherMode = if (encrypt) Cipher.ENCRYPT_MODE else Cipher.DECRYPT_MODE
    val secretKey = SecretKeySpec(key, algoName)
    when (mode) {
        AlgorithmMode.CBC -> {
            val spec = when {
                iv == null -> IvParameterSpec(ByteArray(cipher.blockSize))
                iv.size == cipher.blockSize -> IvParameterSpec(iv)
                iv.size > cipher.blockSize -> IvParameterSpec(iv, 0, cipher.blockSize)
                else -> {
                    val paddedIv = ByteArray(cipher.blockSize)
                    iv.copyInto(paddedIv)
                    IvParameterSpec(paddedIv)
                }
            }
            cipher.init(cipherMode, secretKey, spec)
        }
        AlgorithmMode.ECB -> {
            cipher.init(cipherMode, secretKey)
        }
    }
    return cipher.doFinal(data)
}

fun encrypt(data: ByteArray?, key: ByteArray?, type: String?): ByteArray? {
    return processWithIv(data, key, iv = null, type, encrypt = true)
}

fun encrypt_iv(data: ByteArray?, key: ByteArray?, iv: ByteArray?, type: String?): ByteArray? {
    if (iv == null) {
        return null
    }
    return processWithIv(data, key, iv, type, encrypt = true)
}

fun decrypt(data: ByteArray?, key: ByteArray?, type: String?): ByteArray? {
    return processWithIv(data, key, iv = null, type, encrypt = false)
}

fun decrypt_iv(data: ByteArray?, key: ByteArray?, iv: ByteArray?, type: String?): ByteArray? {
    if (iv == null) {
        return null
    }
    return processWithIv(data, key, iv, type, encrypt = false)
}