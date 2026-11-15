package com.kanaf.alrasby.engine

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import javax.crypto.KeyGenerator
import org.junit.Assert.*
import org.junit.Test

class VaultCipherTest {
    private val key = KeyGenerator.getInstance("AES").apply { init(256) }.generateKey()
    private val id = "c31779f8-e90d-4d95-b8aa-c01cf414bff2"

    private fun sealed(bytes: ByteArray): ByteArray = ByteArrayOutputStream().also {
        VaultCipher.encrypt(ByteArrayInputStream(bytes), it, key, id)
    }.toByteArray()

    private fun opened(envelope: ByteArray, itemId: String = id): ByteArray =
        ByteArrayOutputStream().also {
            VaultCipher.decrypt(ByteArrayInputStream(envelope), it, key, itemId)
        }.toByteArray()

    @Test fun actualAeadRoundTrip() {
        val original = ByteArray(90_001) { (it % 251).toByte() }
        val sealed = sealed(original)
        assertFalse(original.contentEquals(sealed))
        assertArrayEquals(original, opened(sealed))
    }

    @Test fun emptyFileStillAuthenticates() {
        assertArrayEquals(byteArrayOf(), opened(sealed(byteArrayOf())))
    }

    @Test fun bitFlipIsRejected() {
        val envelope = sealed("user-selected-document".toByteArray())
        envelope[20] = (envelope[20].toInt() xor 8).toByte()
        assertThrows(Exception::class.java) { opened(envelope) }
    }

    @Test fun truncatedAuthenticationTagIsRejected() {
        val envelope = sealed("sample".toByteArray())
        assertThrows(Exception::class.java) { opened(envelope.copyOf(envelope.size - 1)) }
    }

    @Test fun authenticationFailureNeverReleasesPartialPlaintext() {
        val original = ByteArray(120_000) { (it % 157).toByte() }
        val tampered = sealed(original).also {
            it[it.lastIndex] = (it.last().toInt() xor 1).toByte()
        }
        val stage = ByteArrayOutputStream()
        assertThrows(Exception::class.java) {
            VaultCipher.decrypt(ByteArrayInputStream(tampered), stage, key, id)
        }
        assertEquals("No unauthenticated plaintext may be released", 0, stage.size())
    }

    @Test fun trailingCiphertextAndMissingTagAreRejectedWithoutOutput() {
        val valid = sealed("safe".toByteArray())
        val truncated = valid.copyOf(4 + 12 + 15)
        val stage = ByteArrayOutputStream()
        assertThrows(Exception::class.java) {
            VaultCipher.decrypt(ByteArrayInputStream(truncated), stage, key, id)
        }
        assertEquals(0, stage.size())
    }

    @Test fun wrongItemIdCannotDecrypt() {
        assertThrows(Exception::class.java) { opened(sealed("sample".toByteArray()), "different-id") }
    }

    @Test fun invalidHeaderCannotDecrypt() {
        val envelope = sealed("sample".toByteArray()).apply { this[0] = 0 }
        assertThrows(Exception::class.java) { opened(envelope) }
    }

    @Test fun oversizedInputIsRejected() {
        val input = ByteArray(VaultCipher.MAX_PLAINTEXT_BYTES.toInt() + 1)
        assertThrows(Exception::class.java) { sealed(input) }
    }
}
