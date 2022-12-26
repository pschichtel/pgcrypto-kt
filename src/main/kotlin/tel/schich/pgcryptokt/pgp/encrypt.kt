package tel.schich.pgcryptokt.pgp

import org.bouncycastle.openpgp.PGPCompressedDataGenerator
import org.bouncycastle.openpgp.PGPEncryptedDataGenerator
import org.bouncycastle.openpgp.PGPLiteralData
import org.bouncycastle.openpgp.PGPLiteralDataGenerator
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection
import org.bouncycastle.openpgp.operator.bc.BcPGPDataEncryptorBuilder
import org.bouncycastle.openpgp.operator.bc.BcPublicKeyKeyEncryptionMethodGenerator
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.OutputStream
import java.lang.IllegalArgumentException
import java.util.Date
import java.util.Random
import kotlin.math.roundToInt

private fun remap(value: Int, from: IntRange, to: IntRange): Int {
    return to.first + (value / (from.last - from.first).toDouble() * (to.last - to.first)).roundToInt()
}

private fun randomIn(random: Random, range: IntRange): Int {
    return range.first + (random.nextDouble() * (range.last - range.first)).roundToInt()
}

private fun digestCalculator(algo: S2kDigestAlgo) = digestCalculatorProvider.get(algo.tag)

sealed interface EncryptionMode {
    val options: EncryptionOptions
    class PublicKey(val key: ByteArray, override val options: AsymmetricEncryptionOptions) : EncryptionMode
    class Password(val password: CharArray, override val options: SymmetricEncryptionOptions) : EncryptionMode
}

fun encrypt(data: ByteArray, mode: EncryptionMode, dataType: DataType): ByteArray {

    val secureRandom = random.get()
    val cipherAlgo = mode.options.cipherAlgo ?: CipherAlgo.AES128
    val encryptorBuilder = BcPGPDataEncryptorBuilder(cipherAlgo.tag)
        .setSecureRandom(secureRandom)
        .setWithIntegrityPacket(mode.options.disableMdc != true)
    val dataGenerator = PGPEncryptedDataGenerator(encryptorBuilder)

    val encryptionMethodGenerator = when (mode) {
        is EncryptionMode.PublicKey -> {
            val keys = PGPPublicKeyRingCollection(ByteArrayInputStream(mode.key), fingerprintCalculator)
                .keyRings
                .asSequence()
                .flatMap { it.publicKeys.asSequence() }
                .filter { it.isEncryptionKey && !it.isMasterKey }
                .toList()

            if (keys.isEmpty()) {
                throw IllegalArgumentException("No public keys detected in key!")
            }
            if (keys.size > 1) {
                throw IllegalArgumentException("Multiple public keys detected in key!")
            }

            listOf(BcPublicKeyKeyEncryptionMethodGenerator(keys.first()))
        }
        is EncryptionMode.Password -> {
            val sessKeyEncryptionAlgo =
                if (mode.options.sessKey == true) mode.options.s2kCipherAlgo?.tag ?: cipherAlgo.tag
                else cipherAlgo.tag

            val mainGenerator = when (mode.options.s2kMode ?: S2kMode.VARIABLE_ITERATION_COUNT) {
                S2kMode.NO_SALT -> CustomSessKeyAlgoBcPBEKeyEncryptionMethodGenerator(sessKeyEncryptionAlgo, mode.password)
                S2kMode.FIXED_ITERATION_COUNT -> {
                    CustomSessKeyAlgoBcPBEKeyEncryptionMethodGenerator(sessKeyEncryptionAlgo, mode.password, digestCalculator(mode.options.s2kDigestAlgo ?: S2kDigestAlgo.SHA1))
                }

                S2kMode.VARIABLE_ITERATION_COUNT -> {
                    val iterationCount =
                        mode.options.s2kCount?.count ?: randomIn(secureRandom, S2kIterationCount.DefaultIterationsRange)
                    val singleByteIterationCount = remap(iterationCount, S2kIterationCount.ValidRange, 0..255)
                    CustomSessKeyAlgoBcPBEKeyEncryptionMethodGenerator(
                        sessKeyEncryptionAlgo,
                        mode.password,
                        digestCalculator(mode.options.s2kDigestAlgo ?: S2kDigestAlgo.SHA1),
                        singleByteIterationCount
                    )
                }
            }
            if (mode.options.sessKey == true) {
                listOf(mainGenerator, DummyEncryptionMethodGenerator)
            } else {
                listOf(mainGenerator)
            }
        }
    }

    for (methodGenerator in encryptionMethodGenerator) {
        dataGenerator.addMethod(methodGenerator)
    }

    val output = ByteArrayOutputStream()
    var outStream: OutputStream = dataGenerator.open(output, ByteArray(1 shl 14))

    val compressor = (mode.options.compressAlgo ?: CompressionAlgo.NONE).tag?.let(::PGPCompressedDataGenerator)
    if (compressor != null) {
        outStream = compressor.open(outStream)
    }
    val type = when (dataType) {
        DataType.TEXT -> PGPLiteralData.TEXT
        DataType.UNICODE -> PGPLiteralData.UTF8
        DataType.BINARY -> PGPLiteralData.BINARY
    }
    val literalDataGenerator = PGPLiteralDataGenerator()
    outStream = literalDataGenerator.open(outStream, type, "", Date(), ByteArray(1 shl 14))
    if (mode.options.convertCrLf == true) {
        outStream = LfToCrlfOutputStream(outStream)
    }

    outStream.write(data)
    outStream.flush()
    literalDataGenerator.close()
    compressor?.close()
    dataGenerator.close()
    outStream.close()

    return output.toByteArray()
}