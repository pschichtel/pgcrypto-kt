package tel.schich.pgcryptokt

import org.intellij.lang.annotations.Language
import org.junit.jupiter.api.Test
import org.postgresql.ds.PGSimpleDataSource
import org.testcontainers.containers.PostgreSQLContainer
import org.testcontainers.junit.jupiter.Container
import org.testcontainers.junit.jupiter.Testcontainers
import org.testcontainers.utility.DockerImageName
import java.sql.Connection
import kotlin.test.assertEquals

@Testcontainers
class PostgresTests {
    @Test
    fun decrypt() {
        val clearData = "a".repeat(70000)
        val passphrase = "password"
        val encryptedData = queryOne<ByteArray>("SELECT pgp_sym_encrypt(?, ?);", clearData, passphrase)
        val dbDecryptedData = queryOne<String>("SELECT pgp_sym_decrypt(CAST(? AS BYTEA), ?);", encryptedData, passphrase)
        val localDecryptedData = pgp_sym_decrypt(encryptedData, passphrase)

        assertEquals(dbDecryptedData, localDecryptedData)
        assertEquals(clearData, localDecryptedData)
    }

    @Test
    fun encrypt() {

        val clearData = "a".repeat(70000)
        val passphrase = "password"
        val dbEncryptedData = queryOne<ByteArray>("SELECT pgp_sym_encrypt(?, ?);", clearData, passphrase)
        val localEncryptedData = pgp_sym_encrypt(clearData, passphrase)

        val decryptedFromDb = pgp_sym_decrypt(dbEncryptedData, passphrase)
        val decryptedFromLocal = pgp_sym_decrypt(localEncryptedData, passphrase)

        assertEquals(decryptedFromDb, decryptedFromLocal)
    }

    @Test
    fun decryptRoundTrip() {
        val clearData = "a".repeat(70000)
        val passphrase = "password"
        val encryptedData = queryOne<ByteArray>("SELECT pgp_sym_encrypt(?, ?);", clearData, passphrase)
        val decryptedData = pgp_sym_decrypt(encryptedData, passphrase)

        assertEquals(clearData, decryptedData)
    }

    @Test
    fun encryptRoundTrip() {
        val clearData = "a".repeat(70000)
        val passphrase = "password"
        val encryptedData = pgp_sym_encrypt(clearData, passphrase)
        val decryptedData = queryOne<String>("SELECT pgp_sym_decrypt(CAST(? AS BYTEA), ?);", encryptedData, passphrase)

        assertEquals(clearData, decryptedData)
    }

    @Test
    fun encryptWithCrLf() {
        val clearData = "a\nb"
        val passphrase = "password"
        val encryptedData = pgp_sym_encrypt(clearData, passphrase, "convert-crlf=1")

        assertEquals(clearData, queryOne("SELECT pgp_sym_decrypt(CAST(? AS BYTEA), ?, 'convert-crlf=1');", encryptedData, passphrase))
        assertEquals("a\r\nb", queryOne("SELECT pgp_sym_decrypt(CAST(? AS BYTEA), ?, 'convert-crlf=0');", encryptedData, passphrase))
    }

    @Test
    fun decryptWithCrLf() {
        val clearData = "a\nb"
        val passphrase = "password"
        val encryptedData = queryOne<ByteArray>("SELECT pgp_sym_encrypt(?, ?, 'convert-crlf=1');", clearData, passphrase)

        assertEquals(clearData, pgp_sym_decrypt(encryptedData, passphrase, "convert-crlf=1"))
        assertEquals("a\r\nb", pgp_sym_decrypt(encryptedData, passphrase, "convert-crlf=0"))
    }

    @Test
    fun encryptWithAes256() {
        val clearData = "a\nb"
        val passphrase = "password"
        val encryptedData = pgp_sym_encrypt(clearData, passphrase, "cipher-algo=aes256")

        assertEquals(clearData, queryOne("SELECT pgp_sym_decrypt(CAST(? AS BYTEA), ?);", encryptedData, passphrase))
    }

    @Test
    fun decryptWithAes256() {
        val clearData = "a\nb"
        val passphrase = "password"
        val encryptedData = queryOne<ByteArray>("SELECT pgp_sym_encrypt(?, ?, 'cipher-algo=aes256');", clearData, passphrase)

        assertEquals(clearData, pgp_sym_decrypt(encryptedData, passphrase))
    }

    @Test
    fun encryptWithCompression() {
        val clearData = "a\nb"
        val passphrase = "password"


        assertEquals(
            clearData,
            queryOne(
                "SELECT pgp_sym_decrypt(CAST(? AS BYTEA), ?);",
                pgp_sym_encrypt(clearData, passphrase, "compress-algo=0,compress-level=9"),
                passphrase
            )
        )

        assertEquals(
            clearData,
            queryOne(
                "SELECT pgp_sym_decrypt(CAST(? AS BYTEA), ?);",
                pgp_sym_encrypt(clearData, passphrase, "compress-algo=1,compress-level=9"),
                passphrase
            )
        )

        assertEquals(
            clearData,
            queryOne(
                "SELECT pgp_sym_decrypt(CAST(? AS BYTEA), ?);",
                pgp_sym_encrypt(clearData, passphrase, "compress-algo=2,compress-level=9"),
                passphrase
            )
        )
    }

    @Test
    fun decryptWithCompression() {
        val clearData = "a\nb"
        val passphrase = "password"

        assertEquals(
            clearData,
            pgp_sym_decrypt(
                queryOne(
                    "SELECT pgp_sym_encrypt(?, ?, 'compress-algo=0,compress-level=9');",
                    clearData,
                    passphrase
                ), passphrase
            )
        )

        assertEquals(
            clearData,
            pgp_sym_decrypt(
                queryOne(
                    "SELECT pgp_sym_encrypt(?, ?, 'compress-algo=1,compress-level=9');",
                    clearData,
                    passphrase
                ), passphrase
            )
        )

        assertEquals(
            clearData,
            pgp_sym_decrypt(
                queryOne(
                    "SELECT pgp_sym_encrypt(?, ?, 'compress-algo=2,compress-level=9');",
                    clearData,
                    passphrase
                ), passphrase
            )
        )
    }

    @Test
    fun encryptWithS2k() {
        val clearData = "a\nb"
        val passphrase = "password"
        val encryptedData = pgp_sym_encrypt(clearData, passphrase, "s2k-mode=3,s2k-digest-algo=md5,s2k-cipher-algo=aes256")

        assertEquals(clearData, queryOne("SELECT pgp_sym_decrypt(CAST(? AS BYTEA), ?);", encryptedData, passphrase))
    }

    @Test
    fun decryptWithS2k() {
        val clearData = "a\nb"
        val passphrase = "password"
        val encryptedData = queryOne<ByteArray>("SELECT pgp_sym_encrypt(?, ?, 's2k-mode=3,s2k-digest-algo=md5,s2k-cipher-algo=aes256');", clearData, passphrase)

        assertEquals(clearData, pgp_sym_decrypt(encryptedData, passphrase))
    }

    companion object {
        @JvmStatic
        @Container
        private val postgresContainer = PostgreSQLContainer(DockerImageName.parse("postgres:13.9"))

        private val dataSource = lazy {
            val dataSource = PGSimpleDataSource()
            dataSource.setUrl(postgresContainer.jdbcUrl)
            dataSource.user = postgresContainer.username
            dataSource.password = postgresContainer.password
            dataSource.connection.use(::initializeDb)
            dataSource
        }

        private fun initializeDb(connection: Connection) {
            runSql(connection, "CREATE EXTENSION IF NOT EXISTS pgcrypto;")
        }

        private inline fun <T> withConnection(block: Connection.() -> T): T {
            return dataSource.value.connection.use(block)
        }

        private fun runSql(connection: Connection, @Language("SQL") sql: String) {
            connection.createStatement().use {
                it.execute(sql)
            }
        }

        private fun runSql(@Language("SQL") sql: String) {
            withConnection {
                runSql(this, sql)
            }
        }

        private inline fun <reified T : Any> queryOne(@Language("SQL") sql: String, vararg args: Any?): T {
            return withConnection {
                prepareStatement(sql).use {
                    for ((i, arg) in args.withIndex()) {
                        it.setObject(i + 1, arg)
                    }
                    val result = it.executeQuery()
                    result.next()
                    when (T::class) {
                        String::class -> result.getString(1)
                        ByteArray::class -> result.getBytes(1)
                        Int::class -> result.getInt(1)
                        else -> result.getObject(1)
                    } as T
                }
            }
        }
    }

}