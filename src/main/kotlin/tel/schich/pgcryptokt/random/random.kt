package tel.schich.pgcryptokt.random

import java.util.UUID

const val MAX_RANDOM_BYTES = 1024

fun get_random_bytes(count: Int?): ByteArray? {
    if (count == null) {
        return null
    }
    if (count > MAX_RANDOM_BYTES) {
        throw IllegalArgumentException("A maximum of $MAX_RANDOM_BYTES can be fetched at once, but $count were requested!")
    }
    val output = ByteArray(count)
    tel.schich.pgcryptokt.random.get().nextBytes(output)
    return output
}

fun gen_random_uuid(): UUID {
    return UUID.randomUUID()
}