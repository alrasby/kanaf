package com.kanaf.alrasby.engine

import org.junit.Assert.*
import org.junit.Test
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.security.MessageDigest

class VerifiedSignatureBundleTest {
    private val feed = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\tEICAR.TEST\n".toByteArray(Charsets.UTF_8)
    private val sha = MessageDigest.getInstance("SHA-256").digest(feed)
        .joinToString("") { "%02x".format(it.toInt() and 0xff) }

    private fun encoded(version: Long = 7L): ByteArray = ByteArrayOutputStream().also {
        VerifiedSignatureBundle.write(it, version, sha, feed)
    }.toByteArray()

    @Test fun roundTripRetainsVersionAndDigest() {
        val restored = VerifiedSignatureBundle.read(ByteArrayInputStream(encoded()))
        assertEquals(7L, restored.version)
        assertEquals(sha, restored.sha256)
        assertArrayEquals(feed, restored.bytes)
    }

    @Test fun interruptedWriteNeverBecomesAValidBundle() {
        val content = encoded()
        assertThrows(Exception::class.java) {
            VerifiedSignatureBundle.read(ByteArrayInputStream(content.copyOf(content.size - 3)))
        }
    }

    @Test fun changedPayloadFailsClosed() {
        val corrupted = encoded().apply { this[lastIndex] = (this[lastIndex].toInt() xor 1).toByte() }
        assertThrows(IllegalArgumentException::class.java) {
            VerifiedSignatureBundle.read(ByteArrayInputStream(corrupted))
        }
    }

    @Test fun oversizedLengthIsRejectedBeforeAllocating() {
        val corrupted = encoded().apply { this[16] = 127 }
        assertThrows(IllegalArgumentException::class.java) {
            VerifiedSignatureBundle.read(ByteArrayInputStream(corrupted))
        }
    }

    @Test fun trailingBytesAreRejected() {
        assertThrows(IllegalArgumentException::class.java) {
            VerifiedSignatureBundle.read(ByteArrayInputStream(encoded() + byteArrayOf(0)))
        }
    }

    @Test fun malformedHeaderIsRejected() {
        val corrupted = encoded().apply { this[0] = 0 }
        assertThrows(IllegalArgumentException::class.java) {
            VerifiedSignatureBundle.read(ByteArrayInputStream(corrupted))
        }
    }

    @Test fun mismatchedManifestDigestIsRejectedBeforeCommit() {
        assertThrows(IllegalArgumentException::class.java) {
            VerifiedSignatureBundle.write(ByteArrayOutputStream(), 8L, "f".repeat(64), feed)
        }
    }

    @Test fun rollbackFloorIncludesLegacyVersion() {
        assertThrows(IllegalArgumentException::class.java) {
            VerifiedSignatureBundle.requireNewer(9L, currentVersion = 8L, legacyVersion = 9L)
        }
        assertThrows(IllegalArgumentException::class.java) {
            VerifiedSignatureBundle.requireNewer(7L, currentVersion = 8L, legacyVersion = 0L)
        }
        VerifiedSignatureBundle.requireNewer(10L, currentVersion = 8L, legacyVersion = 9L)
    }

    @Test fun invalidVersionAndZeroByteFeedAreRejected() {
        assertThrows(IllegalArgumentException::class.java) {
            VerifiedSignatureBundle.write(ByteArrayOutputStream(), 0L, sha, feed)
        }
        assertThrows(IllegalArgumentException::class.java) {
            VerifiedSignatureBundle.write(ByteArrayOutputStream(), 1L, sha, byteArrayOf())
        }
    }
}
