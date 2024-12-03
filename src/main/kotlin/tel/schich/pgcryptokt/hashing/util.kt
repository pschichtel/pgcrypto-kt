package tel.schich.pgcryptokt.hashing

internal fun mapHashAlgorithmName(name: String): String = when (name) {
    "sha224" -> "sha-224"
    "sha256" -> "sha-256"
    "sha384" -> "sha-384"
    "sha512" -> "sha-512"
    else -> name
}
