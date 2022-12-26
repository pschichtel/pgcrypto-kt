package tel.schich.pgcryptokt

import org.bouncycastle.bcpg.CompressionAlgorithmTags
import org.bouncycastle.bcpg.HashAlgorithmTags
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags
import java.lang.IllegalArgumentException
import java.lang.NumberFormatException

enum class CipherAlgo(val tag: Int) {
    BF(SymmetricKeyAlgorithmTags.BLOWFISH),
    AES128(SymmetricKeyAlgorithmTags.AES_128),
    AES192(SymmetricKeyAlgorithmTags.AES_192),
    AES256(SymmetricKeyAlgorithmTags.AES_256),
    `3DES`(SymmetricKeyAlgorithmTags.TRIPLE_DES),
    CAST5(SymmetricKeyAlgorithmTags.CAST5),
}

enum class CompressionAlgo(val tag: Int?) {
    NONE(tag = null),
    ZIP(CompressionAlgorithmTags.ZIP),
    ZLIB(CompressionAlgorithmTags.ZLIB),
}

@JvmInline
value class CompressionLevel(val level: Int)

enum class S2kMode {
    NO_SALT,
    FIXED_ITERATION_COUNT,
    VARIABLE_ITERATION_COUNT,
}

@JvmInline
value class S2kIterationCount(val count: Int) {
    companion object {
        val ValidRange = 1024..65011712
        val DefaultIterationsRange = 65536..253952
    }
}

enum class S2kDigestAlgo(val tag: Int) {
    MD5(HashAlgorithmTags.MD5),
    SHA1(HashAlgorithmTags.SHA1),
}

enum class S2kCipherAlgo(val tag: Int) {
    BF(SymmetricKeyAlgorithmTags.BLOWFISH),
    AES(SymmetricKeyAlgorithmTags.AES_128),
    AES128(SymmetricKeyAlgorithmTags.AES_128),
    AES192(SymmetricKeyAlgorithmTags.AES_192),
    AES256(SymmetricKeyAlgorithmTags.AES_256),
}

sealed interface Options {
    val convertCrLf: Boolean?
}

sealed interface EncryptionOptions : Options {
    val cipherAlgo: CipherAlgo?
    val compressAlgo: CompressionAlgo?
    val compressLevel: CompressionLevel?
    val disableMdc: Boolean?
    val unicodeMode: Boolean?
}

data class SymmetricEncryptionOptions(
    override val cipherAlgo: CipherAlgo? = null,
    override val compressAlgo: CompressionAlgo? = null,
    override val compressLevel: CompressionLevel? = null,
    override val convertCrLf: Boolean? = null,
    override val disableMdc: Boolean? = null,
    val sessKey: Boolean? = null,
    val s2kMode: S2kMode? = null,
    val s2kCount: S2kIterationCount? = null,
    val s2kDigestAlgo: S2kDigestAlgo? = null,
    val s2kCipherAlgo: S2kCipherAlgo? = null,
    override val unicodeMode: Boolean? = null,
) : EncryptionOptions

data class AsymmetricEncryptionOptions(
    override val cipherAlgo: CipherAlgo? = null,
    override val compressAlgo: CompressionAlgo? = null,
    override val compressLevel: CompressionLevel? = null,
    override val convertCrLf: Boolean? = null,
    override val disableMdc: Boolean? = null,
    override val unicodeMode: Boolean? = null,
) : EncryptionOptions

sealed interface DecryptionOptions : Options

data class SymmetricDecryptionOptions(
    override val convertCrLf: Boolean? = null,
) : DecryptionOptions

data class AsymmetricDecryptionOptions(
    override val convertCrLf: Boolean? = null,
) : DecryptionOptions

private val optionSeparator = """\s*,\s*""".toRegex()

private fun parseOptions(optionsString: String): MutableMap<String, String> {
    return optionsString.trim().split(optionSeparator)
        .filter { it.isNotBlank() }
        .associate { option ->
            val equalsPosition = option.indexOf('=')
            if (equalsPosition == -1) {
                throw IllegalArgumentException("Failed to parse option: <$option> in <$optionsString>: Missing equals sign")
            }

            Pair(option.substring(0, equalsPosition).trim().lowercase(), option.substring(equalsPosition + 1).trim())
        }
        .toMutableMap()
}

private fun parseBooleanOption(options: MutableMap<String, String>, name: String): Boolean? {
    return when (val value = options.remove(name)) {
        null -> null
        "0" -> false
        "1" -> true
        else -> throw IllegalArgumentException("Failed to parse boolean option $name: Unknown value $value")
    }
}

private fun parseS2kCountOption(options: MutableMap<String, String>): S2kIterationCount? {
    val value = options.remove("s2k-count") ?: return null
    val intValue = try {
        value.toInt()
    } catch (e: NumberFormatException) {
        throw IllegalArgumentException("Failed to parse option s2k-count: value <$value> is not a number!", e)
    }
    if (intValue !in S2kIterationCount.ValidRange) {
        throw IllegalArgumentException("Failed to parse option s2k-count: value <$intValue> is out of range!")
    }
    return S2kIterationCount(intValue)
}

private fun <T : Any> parseEnumOptions(options: MutableMap<String, String>, name: String, mappings: Map<String, T>): T? {
    val value = options.remove(name)?.lowercase() ?: return null
    return mappings[value] ?: throw IllegalArgumentException("Failed to parse option $name: Unknown value $value")
}

private val cipherAlgoMappings = mapOf(
    "bf" to CipherAlgo.BF,
    "aes128" to CipherAlgo.AES128,
    "aes192" to CipherAlgo.AES192,
    "aes256" to CipherAlgo.AES256,
    "3des" to CipherAlgo.`3DES`,
    "cast5" to CipherAlgo.CAST5,
)

private val compressAlgoMappings = mapOf(
    "0" to CompressionAlgo.NONE,
    "1" to CompressionAlgo.ZIP,
    "2" to CompressionAlgo.ZLIB,
)

private val compressLevelMappings = (0..9).map(::CompressionLevel).associateBy { it.level.toString() }

private val s2kModeMappings = mapOf(
    "0" to S2kMode.NO_SALT,
    "1" to S2kMode.FIXED_ITERATION_COUNT,
    "3" to S2kMode.VARIABLE_ITERATION_COUNT,
)

private val s2kDigestAlgoMappings = mapOf(
    "md5" to S2kDigestAlgo.MD5,
    "sha1" to S2kDigestAlgo.SHA1,
)

private val s2kCipherAlgoMappings = mapOf(
    "bf" to S2kCipherAlgo.BF,
    "aes" to S2kCipherAlgo.AES,
    "aes128" to S2kCipherAlgo.AES128,
    "aes192" to S2kCipherAlgo.AES192,
    "aes256" to S2kCipherAlgo.AES256,
)

fun verifyAllOptionsConsumed(options: Map<String, String>) {
    if (options.isNotEmpty()) {
        error("Received unknown options: $options")
    }
}

fun parseSymmetricEncryptionOptionsString(optionsString: String?): SymmetricEncryptionOptions {
    val options = parseOptions(optionsString ?: return SymmetricEncryptionOptions())
    val result = SymmetricEncryptionOptions(
        cipherAlgo = parseEnumOptions(options, name = "cipher-algo", cipherAlgoMappings),
        compressAlgo = parseEnumOptions(options, name = "compress-algo", compressAlgoMappings),
        compressLevel = parseEnumOptions(options, name = "compress-level", compressLevelMappings),
        convertCrLf = parseBooleanOption(options, name = "convert-crlf"),
        disableMdc = parseBooleanOption(options, name = "disable-mdc"),
        sessKey = parseBooleanOption(options, name = "sess-key"),
        s2kMode = parseEnumOptions(options, name = "s2k-mode", s2kModeMappings),
        s2kCount = parseS2kCountOption(options),
        s2kDigestAlgo = parseEnumOptions(options, name = "s2k-digest-algo", s2kDigestAlgoMappings),
        s2kCipherAlgo = parseEnumOptions(options, name = "s2k-cipher-algo", s2kCipherAlgoMappings),
        unicodeMode = parseBooleanOption(options, name = "unicode-mode"),
    )
    verifyAllOptionsConsumed(options)
    return result
}

fun parseAsymmetricEncryptionOptionsString(optionsString: String?): AsymmetricEncryptionOptions {
    val options = parseOptions(optionsString ?: return AsymmetricEncryptionOptions())
    val result = AsymmetricEncryptionOptions(
        cipherAlgo = parseEnumOptions(options, name = "cipher-algo", cipherAlgoMappings),
        compressAlgo = parseEnumOptions(options, name = "compress-algo", compressAlgoMappings),
        compressLevel = parseEnumOptions(options, "compress-level", compressLevelMappings),
        convertCrLf = parseBooleanOption(options, name = "convert-crlf"),
        disableMdc = parseBooleanOption(options, name = "disable-mdc"),
        unicodeMode = parseBooleanOption(options, name = "unicode-mode"),
    )
    verifyAllOptionsConsumed(options)
    return result
}

fun parseSymmetricDecryptionOptionsString(optionsString: String?): SymmetricDecryptionOptions {
    val options = parseOptions(optionsString ?: return SymmetricDecryptionOptions())
    val result = SymmetricDecryptionOptions(
        convertCrLf = parseBooleanOption(options, name = "convert-crlf"),
    )
    verifyAllOptionsConsumed(options)
    return result
}

fun parseAsymmetricDecryptionOptionsString(optionsString: String?): AsymmetricDecryptionOptions {
    val options = parseOptions(optionsString ?: return AsymmetricDecryptionOptions())
    val result = AsymmetricDecryptionOptions(
        convertCrLf = parseBooleanOption(options, name = "convert-crlf"),
    )
    verifyAllOptionsConsumed(options)
    return result
}