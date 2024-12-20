@file:Suppress("FunctionNaming", "FunctionName")

package tel.schich.pgcryptokt.random

import tel.schich.pgcryptokt.threadLocalSecureRandom
import java.util.UUID

const val MAX_RANDOM_BYTES = 1024

fun get_random_bytes(count: Int): ByteArray {
    require(count <= MAX_RANDOM_BYTES) { "A maximum of $MAX_RANDOM_BYTES can be fetched at once, but $count were requested!" }
    val output = ByteArray(count)
    threadLocalSecureRandom.get().nextBytes(output)
    return output
}

fun gen_random_uuid(): UUID {
    return UUID.randomUUID()
}
