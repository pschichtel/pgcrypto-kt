package tel.schich.pgcryptokt

import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows

class OptionParsingTests {
    @Test
    fun rejectsUnknownOption() {
        assertThrows<IllegalStateException> {
            pgp_sym_encrypt("some test", "password", "cipher=aes256")
        }
        assertThrows<IllegalStateException> {
            pgp_sym_encrypt_bytea("some test".toByteArray(), "password", "cipher=aes256")
        }
        assertThrows<IllegalStateException> {
            pgp_sym_decrypt("some test".toByteArray(), "password", "cipher=aes256")
        }
        assertThrows<IllegalStateException> {
            pgp_sym_decrypt_bytea("some test".toByteArray(), "password", "cipher=aes256")
        }
    }
}