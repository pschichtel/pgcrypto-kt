package tel.schich.pgcryptokt

import org.junit.jupiter.api.Test
import tel.schich.pgcryptokt.pgp.CrLfToLfInputStream
import tel.schich.pgcryptokt.pgp.LfToCrlfOutputStream
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import kotlin.test.assertContentEquals

class CrLfTests {
    @Test
    fun lfToCrLf() {
        val output = ByteArrayOutputStream()
        val stream = LfToCrlfOutputStream(output)
        stream.write("a\nb".toByteArray())
        stream.flush()
        stream.close()

        assertContentEquals("a\r\nb".toByteArray(), output.toByteArray())
    }

    @Test
    fun crLfToLf() {
        val stream = CrLfToLfInputStream(ByteArrayInputStream("a\r\nb".toByteArray()))
        val bytes = stream.readBytes()
        stream.close()

        assertContentEquals("a\nb".toByteArray(), bytes)
    }
}
