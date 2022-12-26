package tel.schich.pgcryptokt.pgp

import org.bouncycastle.bcpg.BCPGOutputStream
import org.bouncycastle.bcpg.ContainedPacket
import org.bouncycastle.openpgp.PGPObjectFactory
import org.bouncycastle.openpgp.operator.PGPDigestCalculator
import org.bouncycastle.openpgp.operator.PGPKeyEncryptionMethodGenerator
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator
import org.bouncycastle.openpgp.operator.bc.BcPBEKeyEncryptionMethodGenerator
import org.bouncycastle.openpgp.operator.bc.BcPBESecretKeyDecryptorBuilder
import org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider
import java.security.SecureRandom
import java.util.Random
import kotlin.math.roundToInt

internal val random = ThreadLocal.withInitial { SecureRandom() }

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
