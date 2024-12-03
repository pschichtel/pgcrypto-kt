package tel.schich.pgcryptokt.pgp

import org.bouncycastle.openpgp.PGPObjectFactory
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator
import org.bouncycastle.openpgp.operator.bc.BcPBESecretKeyDecryptorBuilder
import org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider

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
