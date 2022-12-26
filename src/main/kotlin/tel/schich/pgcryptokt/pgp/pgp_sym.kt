package tel.schich.pgcryptokt.pgp

import java.nio.charset.Charset


fun pgp_sym_encrypt(data: String, psw: String, options: String? = null, charset: Charset = Charsets.UTF_8): ByteArray {
    val parsedOptions = parseSymmetricEncryptionOptionsString(options)
    val dataType = if (parsedOptions.unicodeMode == true) DataType.UNICODE else DataType.TEXT
    return encrypt(data.toByteArray(charset), EncryptionMode.Password(psw.toCharArray(), parsedOptions), dataType)
}
fun pgp_sym_encrypt_bytea(data: ByteArray, psw: String, options: String? = null): ByteArray  {
    return encrypt(data, EncryptionMode.Password(psw.toCharArray(), parseSymmetricEncryptionOptionsString(options)), DataType.BINARY)
}

fun pgp_sym_decrypt(msg: ByteArray, psw: String, options: String? = null, charset: Charset = Charsets.UTF_8): String {
    return String(decrypt(msg, DecryptionMode.Password(psw.toCharArray(), parseSymmetricDecryptionOptionsString(options)), textMode = true), charset)
}
fun pgp_sym_decrypt_bytea(msg: ByteArray, psw: String, options: String? = null): ByteArray {
    return decrypt(msg, DecryptionMode.Password(psw.toCharArray(), parseSymmetricDecryptionOptionsString(options)), textMode = false)
}