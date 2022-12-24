package tel.schich.pgcryptokt

import org.bouncycastle.bcpg.BCPGOutputStream
import org.bouncycastle.bcpg.ContainedPacket
import org.bouncycastle.bcpg.HashAlgorithmTags
import org.bouncycastle.crypto.KeyGenerationParameters
import org.bouncycastle.crypto.generators.RSAKeyPairGenerator
import org.bouncycastle.openpgp.PGPEncryptedData
import org.bouncycastle.openpgp.PGPObjectFactory
import org.bouncycastle.openpgp.PGPPublicKey
import org.bouncycastle.openpgp.PGPSecretKey
import org.bouncycastle.openpgp.PGPSignature
import org.bouncycastle.openpgp.operator.PGPDigestCalculator
import org.bouncycastle.openpgp.operator.PGPKeyEncryptionMethodGenerator
import org.bouncycastle.openpgp.operator.bc.BcPBEKeyEncryptionMethodGenerator
import org.bouncycastle.openpgp.operator.bc.BcPBESecretKeyEncryptorBuilder
import org.bouncycastle.openpgp.operator.bc.BcPGPContentSignerBuilder
import org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider
import org.bouncycastle.openpgp.operator.bc.BcPGPKeyPair
import java.security.SecureRandom
import java.util.Date
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

val digestCalculatorProvider = BcPGPDigestCalculatorProvider()

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

fun generateSecretKey(identity: String, passPhrase: String, strength: Int, random: SecureRandom): PGPSecretKey {
    val keyPairGenerator = RSAKeyPairGenerator()
    keyPairGenerator.init(KeyGenerationParameters(random, strength))
    val rsaKeyPair = keyPairGenerator.generateKeyPair()
    val pgpKeyPair = BcPGPKeyPair(PGPPublicKey.RSA_GENERAL, rsaKeyPair, Date())

    val sha1Calc = digestCalculatorProvider.get(HashAlgorithmTags.SHA1)

    return PGPSecretKey(
        PGPSignature.DEFAULT_CERTIFICATION,
        pgpKeyPair,
        identity,
        sha1Calc,
        null,
        null,
        BcPGPContentSignerBuilder(pgpKeyPair.publicKey.algorithm, HashAlgorithmTags.SHA256),
        BcPBESecretKeyEncryptorBuilder(PGPEncryptedData.CAST5, sha1Calc).build(passPhrase.toCharArray()),
    )
}