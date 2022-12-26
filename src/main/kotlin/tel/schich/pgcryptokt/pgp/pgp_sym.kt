package tel.schich.pgcryptokt.pgp

import java.nio.charset.Charset


fun pgp_sym_encrypt(data: String?, psw: String?, options: String? = null, charset: Charset = Charsets.UTF_8): ByteArray? {
    if (data == null || psw == null) {
        return null
    }

    val parsedOptions = parseSymmetricEncryptionOptionsString(options)
    val dataType = if (parsedOptions.unicodeMode == true) DataType.UNICODE else DataType.TEXT
    return encrypt(data.toByteArray(charset), EncryptionMode.Password(psw.toCharArray(), parsedOptions), dataType)
}
fun pgp_sym_encrypt_bytea(data: ByteArray?, psw: String?, options: String? = null): ByteArray?  {
    if (data == null || psw == null) {
        return null
    }

    return encrypt(data, EncryptionMode.Password(psw.toCharArray(), parseSymmetricEncryptionOptionsString(options)), DataType.BINARY)
}

fun pgp_sym_decrypt(msg: ByteArray?, psw: String?, options: String? = null, charset: Charset = Charsets.UTF_8): String? {
    if (msg == null || psw == null) {
        return null
    }

    return String(decrypt(msg, DecryptionMode.Password(psw.toCharArray(), parseSymmetricDecryptionOptionsString(options)), textMode = true), charset)
}
fun pgp_sym_decrypt_bytea(msg: ByteArray?, psw: String?, options: String? = null): ByteArray? {
    if (msg == null || psw == null) {
        return null
    }

    return decrypt(msg, DecryptionMode.Password(psw.toCharArray(), parseSymmetricDecryptionOptionsString(options)), textMode = false)
}