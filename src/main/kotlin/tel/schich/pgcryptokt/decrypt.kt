package tel.schich.pgcryptokt

import org.bouncycastle.bcpg.BCPGInputStream
import org.bouncycastle.bcpg.LiteralDataPacket
import org.bouncycastle.openpgp.PGPEncryptedData
import org.bouncycastle.openpgp.PGPEncryptedDataList
import org.bouncycastle.openpgp.PGPObjectFactory
import org.bouncycastle.openpgp.PGPPBEEncryptedData
import org.bouncycastle.openpgp.PGPPublicKeyEncryptedData
import org.bouncycastle.openpgp.PGPUtil
import org.bouncycastle.openpgp.bc.BcPGPSecretKeyRingCollection
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator
import org.bouncycastle.openpgp.operator.bc.BcPBEDataDecryptorFactory
import org.bouncycastle.openpgp.operator.bc.BcPBESecretKeyDecryptorBuilder
import org.bouncycastle.openpgp.operator.bc.BcPublicKeyDataDecryptorFactory
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.InputStream

class InvalidDataOrPassphraseException(cause: Throwable?) : RuntimeException(cause)

sealed interface DecryptionMode {
    val options: DecryptionOptions
    class PrivateKey(val key: ByteArray, val password: CharArray, override val options: AsymmetricDecryptionOptions) : DecryptionMode
    class Password(val password: CharArray, override val options: SymmetricDecryptionOptions) : DecryptionMode
}

private val fingerprintCalculator = BcKeyFingerprintCalculator()

fun encryptedDataFrom(data: ByteArray): Sequence<PGPEncryptedData> {
    return PGPObjectFactory(data, fingerprintCalculator)
        .asSequence()
        .filterIsInstance<PGPEncryptedDataList>()
        .firstOrNull()
        ?.encryptedDataObjects
        ?.asSequence()
        ?: error("No encrypted data found!")
}

fun decrypt(data: ByteArray, mode: DecryptionMode, textMode: Boolean): ByteArray {
    val output = ByteArrayOutputStream()
    val literalData = try {
        val encryptedData = encryptedDataFrom(data)
        val decryptedData = when (mode) {
            is DecryptionMode.PrivateKey -> {
                val secretKeyDecryptor =
                    BcPBESecretKeyDecryptorBuilder(digestCalculatorProvider).build(mode.password)

                val stream = PGPUtil.getDecoderStream(ByteArrayInputStream(mode.key))
                val keyRingCollection = BcPGPSecretKeyRingCollection(stream)
                stream.close()
                val secretKeyLookup = keyRingCollection
                    .asSequence()
                    .flatMap { it.secretKeys.asSequence() }
                    .associateBy { it.publicKey.keyID }

                encryptedData
                    .filterIsInstance<PGPPublicKeyEncryptedData>()
                    .map {
                        val secretKey = secretKeyLookup[it.keyID]
                            ?: error("Wrong secret key way given!")

                        val decryptorFactory = BcPublicKeyDataDecryptorFactory(secretKey.extractPrivateKey(secretKeyDecryptor))

                        BCPGInputStream(it.getDataStream(decryptorFactory))
                    }
            }
            is DecryptionMode.Password -> {
                encryptedData
                    .filterIsInstance<PGPPBEEncryptedData>()
                    .map {
                        BCPGInputStream(it.getDataStream(BcPBEDataDecryptorFactory(mode.password, digestCalculatorProvider)))
                    }
            }
        }
        decryptedData
            .map { it.readPacket() }
            .filterIsInstance<LiteralDataPacket>()
            .firstOrNull()
            ?: error("The encrypted data did not contain any data!")
    } catch (e: Exception) {
        throw InvalidDataOrPassphraseException(e)
    }

    val type = when (literalData.format) {
        't'.code -> DataType.TEXT
        'u'.code -> DataType.UNICODE
        'b'.code -> DataType.BINARY
        else -> error("The decrypted data does not have a valid data type!")
    }

    if (textMode && type != DataType.TEXT && type != DataType.UNICODE) {
        error("Text was expected, but the data was not text!")
    }

    var inStream: InputStream = literalData.inputStream
    if (textMode && mode.options.convertCrLf == true) {
        inStream = CrLfToLfInputStream(inStream)
    }

    inStream.copyTo(output)
    inStream.close()
    output.close()

    return output.toByteArray()
}