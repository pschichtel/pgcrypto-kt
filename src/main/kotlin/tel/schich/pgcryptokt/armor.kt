package tel.schich.pgcryptokt

import org.bouncycastle.bcpg.ArmoredInputStream
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream

fun armor(data: ByteArray, keys: Array<String> = emptyArray(), values: Array<String> = emptyArray()): String {
    if (keys.size != values.size) {
        throw IllegalArgumentException("keys (${keys.size} items) and values (${values.size} items) must have an equal amount of items")
    }
    val output = ByteArrayOutputStream()

    val headers = if (keys.isEmpty()) emptyList() else keys.zip(values)
    val stream = ArmoringOutputStream(output, headers)
    stream.write(data)
    stream.flush()
    stream.close()
    output.close()
    return String(output.toByteArray())
}

fun dearmor(data: String): ByteArray {
    val output = ByteArrayOutputStream()
    val stream = ArmoredInputStream(ByteArrayInputStream(data.toByteArray()))
    stream.copyTo(output)
    stream.close()
    output.close()
    stream.close()
    return output.toByteArray()
}

fun pgp_armor_headers(data: String, keys: MutableList<String>? = null, values: MutableList<String>? = null): List<Pair<String, String>> {
    return ArmoredInputStream(ByteArrayInputStream(data.toByteArray())).use { stream ->
        val headers = stream.armorHeaders ?: return emptyList()
        buildList {
            for (armorHeader in headers) {
                val colonPosition = armorHeader.indexOf(':')
                if (colonPosition == -1) {
                    error("Received invalid header: $armorHeader")
                }
                val key = armorHeader.substring(0, colonPosition)
                keys?.add(key)
                val value = armorHeader.substring(colonPosition + 2) // 2 for colon and space
                values?.add(value)
                add(Pair(key, value))
            }
        }
    }
}