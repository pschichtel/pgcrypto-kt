package tel.schich.pgcryptokt.pgp

import java.io.InputStream
import java.io.OutputStream

private const val CR = '\r'.code
private const val LF = '\n'.code

class LfToCrlfOutputStream(private val next: OutputStream) : OutputStream() {
    override fun write(intNext: Int) {
        if (intNext == LF) {
            this.next.write(CR)
        }
        this.next.write(intNext)
    }

    override fun write(b: ByteArray, off: Int, len: Int) {
        if (len == 0) {
            return
        }

        val end = off + len
        var writeFrom = off
        for (i in 0 until len) {
            val offset = off + i
            val current = b[offset]
            if (current == LF.toByte()) {
                if (offset > writeFrom) {
                    next.write(b, writeFrom, offset - writeFrom)
                    writeFrom = offset
                }
                next.write(CR)
            }
        }
        if (end > writeFrom) {
            next.write(b, writeFrom, end - writeFrom)
        }
    }

    override fun flush() {
        next.flush()
    }

    override fun close() {
        next.close()
    }
}

class CrLfToLfInputStream(private val next: InputStream) : InputStream() {
    override fun read(): Int {
        val current = next.read()
        if (current == CR) {
            return next.read()
        }
        return current
    }

    override fun close() {
        next.close()
    }
}
