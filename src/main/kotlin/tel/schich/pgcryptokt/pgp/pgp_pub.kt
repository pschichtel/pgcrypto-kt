package tel.schich.pgcryptokt.pgp

import org.bouncycastle.openpgp.PGPPBEEncryptedData
import org.bouncycastle.openpgp.PGPPublicKeyEncryptedData
import java.nio.charset.Charset


fun pgp_pub_encrypt(data: String, key: ByteArray, options: String? = null, charset: Charset = Charsets.UTF_8): ByteArray {
    val parsedOptions = parseAsymmetricEncryptionOptionsString(options)
    val dataType = if (parsedOptions.unicodeMode == true) DataType.UNICODE else DataType.TEXT
    return encrypt(data.toByteArray(charset), EncryptionMode.PublicKey(key, parsedOptions), dataType)
}
fun pgp_pub_encrypt_bytea(data: ByteArray, key: ByteArray, options: String? = null): ByteArray  {
    return encrypt(data, EncryptionMode.PublicKey(key, parseAsymmetricEncryptionOptionsString(options)), DataType.BINARY)
}

fun pgp_pub_decrypt(msg: ByteArray, key: ByteArray, psw: String = "", options: String? = null, charset: Charset = Charsets.UTF_8): String {
    return String(decrypt(msg, DecryptionMode.PrivateKey(key, psw.toCharArray(), parseAsymmetricDecryptionOptionsString(options)), textMode = true), charset)
}
fun pgp_pub_decrypt_bytea(msg: ByteArray, key: ByteArray, psw: String = "", options: String? = null): ByteArray {
    return decrypt(msg, DecryptionMode.PrivateKey(key, psw.toCharArray(), parseAsymmetricDecryptionOptionsString(options)), textMode = false)
}

fun pgp_key_id(data: ByteArray): String {
    return encryptedDataFrom(data)
        .mapNotNull {
            when (it) {
                is PGPPBEEncryptedData -> "SYMKEY"
                is PGPPublicKeyEncryptedData ->
                    it.keyID.toULong().toString(16).uppercase().padStart(16, '0')
                else -> null
            }
        }
        .firstOrNull()
        ?: error("No encrypted data found!")
}