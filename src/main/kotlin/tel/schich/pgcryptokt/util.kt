package tel.schich.pgcryptokt

import org.bouncycastle.bcpg.BCPGOutputStream
import org.bouncycastle.bcpg.CRC24
import org.bouncycastle.bcpg.ContainedPacket
import org.bouncycastle.openpgp.PGPObjectFactory
import org.bouncycastle.openpgp.operator.PGPDigestCalculator
import org.bouncycastle.openpgp.operator.PGPKeyEncryptionMethodGenerator
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator
import org.bouncycastle.openpgp.operator.bc.BcPBEKeyEncryptionMethodGenerator
import org.bouncycastle.openpgp.operator.bc.BcPBESecretKeyDecryptorBuilder
import org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider
import java.io.OutputStream
import java.util.Random
import kotlin.math.roundToInt

fun remap(value: Int, from: IntRange, to: IntRange): Int {
    return to.first + (value / (from.last - from.first).toDouble() * (to.last - to.first)).roundToInt()
}

fun randomIn(random: Random, range: IntRange): Int {
    return range.first + (random.nextDouble() * (range.last - range.first)).roundToInt()
}

enum class DataType {
    TEXT,
    UNICODE,
    BINARY,
}


val fingerprintCalculator = BcKeyFingerprintCalculator()
val digestCalculatorProvider = BcPGPDigestCalculatorProvider()
val secretKeyDecryptorBuilder = BcPBESecretKeyDecryptorBuilder(digestCalculatorProvider)

fun PGPObjectFactory.asSequence() = sequence {
    var obj: Any? = this@asSequence.nextObject()
    while (obj != null) {
        yield(obj)
        obj = this@asSequence.nextObject()
    }
}

/**
 * This class existing merely to trick bouncycastle into generating session info for PBE encryption
 */
internal object DummyEncryptionMethodGenerator : PGPKeyEncryptionMethodGenerator() {
    override fun generate(encAlgorithm: Int, sessionInfo: ByteArray?): ContainedPacket = DummyContainedPacket

    internal object DummyContainedPacket : ContainedPacket() {
        override fun encode(pOut: BCPGOutputStream?) {}
    }
}

internal class CustomSessKeyAlgoBcPBEKeyEncryptionMethodGenerator : BcPBEKeyEncryptionMethodGenerator {
    private val overrideSessionKeyCipherAlgo: Int

    constructor(overrideSessionKeyCipherAlgo: Int, passPhrase: CharArray) : super(passPhrase) {
        this.overrideSessionKeyCipherAlgo = overrideSessionKeyCipherAlgo
    }

    constructor(overrideSessionKeyCipherAlgo: Int, passPhrase: CharArray, s2kDigestCalculator: PGPDigestCalculator) : super(passPhrase, s2kDigestCalculator) {
        this.overrideSessionKeyCipherAlgo = overrideSessionKeyCipherAlgo
    }

    constructor(overrideSessionKeyCipherAlgo: Int, passPhrase: CharArray, s2kDigestCalculator: PGPDigestCalculator, s2kCount: Int) : super(
        passPhrase,
        s2kDigestCalculator,
        s2kCount
    ) {
        this.overrideSessionKeyCipherAlgo = overrideSessionKeyCipherAlgo
    }

    override fun generate(encAlgorithm: Int, sessionInfo: ByteArray?): ContainedPacket {
        return super.generate(overrideSessionKeyCipherAlgo, sessionInfo)
    }
}

class ArmoringOutputStream(private val next: OutputStream, private val headers: List<Pair<String, String>>) : OutputStream() {
    private var headerWritten: Boolean = false
    private var bytesWritten: Int = 0
    private var crc24 = CRC24()
    private var buf = 0u
    private var pos = 2

    private fun writeBase64Char(index: UInt) {
        next.write(ALPHABET[index.toInt()].code)
        bytesWritten += 1
        if (bytesWritten == 76) {
            next.write(LF)
            bytesWritten = 0
        }
    }

    override fun write(byte: Int) {
        if (!headerWritten) {
            next.write(HEADER)
            for ((name, value) in headers) {
                next.write(name.toByteArray())
                next.write(HEADER_SEPARATOR)
                next.write(value.toByteArray())
                next.write(LF)
            }
            next.write(LF)
            headerWritten = true
        }

        crc24.update(byte)

        buf = buf or (byte.toUByte().toUInt() shl (pos shl 3))
        pos -= 1

        if (pos < 0) {
            writeBase64Char((buf shr 18) and 0b11_11_11u)
            writeBase64Char((buf shr 12) and 0b11_11_11u)
            writeBase64Char((buf shr 6) and 0b11_11_11u)
            writeBase64Char((buf) and 0b11_11_11u)

            pos = 2
            buf = 0u
        }
    }

    override fun flush() {
        if (pos != 2) {
            writeBase64Char((buf shr 18) and 0b11_11_11u)
            writeBase64Char((buf shr 12) and 0b11_11_11u)
            if (pos == 0) {
                writeBase64Char((buf shr 6) and 0b11_11_11u)
            } else {
                next.write(PAD_CHAR)
            }
            next.write(PAD_CHAR)

            pos = 2
        }
        next.flush()
    }

    override fun close() {
        flush()
        next.write(LF)
        next.write(PAD_CHAR)
        writeBase64Char((crc24.value.toUInt() shr 18) and 0b00_11_11_11u)
        writeBase64Char((crc24.value.toUInt() shr 12) and 0b00_11_11_11u)
        writeBase64Char((crc24.value.toUInt() shr 6) and 0b00_11_11_11u)
        writeBase64Char((crc24.value.toUInt()) and 0b00_11_11_11u)
        next.write(FOOTER)
        next.close()
    }

    private companion object {
        private const val LF = '\n'.code
        private const val ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
        private val HEADER = "-----BEGIN PGP MESSAGE-----\n".toByteArray()
        private val FOOTER = "\n-----END PGP MESSAGE-----\n".toByteArray()
        private val HEADER_SEPARATOR = ": ".toByteArray()
        private val PAD_CHAR = "=".toByteArray()
    }
}
