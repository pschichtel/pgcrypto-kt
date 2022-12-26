package tel.schich.pgcryptokt

import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import kotlin.test.assertEquals

class DirectTests {
    @Test
    fun roundTrip() {
        val clear = "some test"
        val passphrase = "password"
        assertEquals(clear, pgp_sym_decrypt(pgp_sym_encrypt(clear, passphrase), passphrase))
    }

    @Test
    fun wrongDecryptionPassphrase() {
        val clear = "some test"
        val encrypted = pgp_sym_encrypt(clear, "password")
        assertThrows<InvalidDataOrPassphraseException> {
            pgp_sym_decrypt(encrypted, "some other password")
        }
    }

    @Test
    fun randomBytesCanBeRequested() {
        assertEquals(MAX_RANDOM_BYTES, get_random_bytes(MAX_RANDOM_BYTES).size)
    }

    @Test
    fun tooManyRandomBytesAreRejected() {
        assertThrows<IllegalArgumentException> {
            get_random_bytes(MAX_RANDOM_BYTES + 1)
        }
    }
}