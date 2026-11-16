package com.kanaf.alrasby.engine

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.Signature
import java.util.Base64
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream
import org.junit.Assert.*
import org.junit.Test

class SignedFeedPackageTest {
    private val database = ("a".repeat(64) + "\tKNOWN_TEST\n").toByteArray()
    private val sha = MessageDigest.getInstance("SHA-256").digest(database)
        .joinToString("") { "%02x".format(it.toInt() and 0xff) }
    private val keys = KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()

    private fun manifest(): ByteArray {
        val payload = "Kanaf-DB-v1\n9\n$sha\n".toByteArray(Charsets.US_ASCII)
        val sign = Signature.getInstance("SHA256withRSA").apply {
            initSign(keys.private)
            update(payload)
        }
        return "9\n$sha\n${Base64.getEncoder().encodeToString(sign.sign())}\n"
            .toByteArray(Charsets.US_ASCII)
    }

    private fun zip(vararg files: Pair<String, ByteArray>): ByteArray =
        ByteArrayOutputStream().also { output ->
            ZipOutputStream(output).use { archive ->
                files.forEach { (name, bytes) ->
                    archive.putNextEntry(ZipEntry(name))
                    archive.write(bytes)
                    archive.closeEntry()
                }
            }
        }.toByteArray()

    @Test fun signedFeedParsesAndAuthenticatesWithExplicitPinnedKey() {
        val parsed = SignedFeedPackage.parse(ByteArrayInputStream(zip(
            "manifest.txt" to manifest(), "signatures.tsv" to database
        )))
        assertEquals(9L, parsed.manifest.version)
        assertArrayEquals(database, parsed.bytes)
        assertTrue(SignedSignatureUpdate.verify(parsed.manifest, keys.public.encoded))
        val other = KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()
        assertFalse(SignedSignatureUpdate.verify(parsed.manifest, other.public.encoded))
    }

    @Test fun rejectsAmbiguousAndUnexpectedEntries() {
        assertThrows(Exception::class.java) {
            SignedFeedPackage.parse(ByteArrayInputStream(zip(
                "manifest.txt" to manifest(), "../signatures.tsv" to database
            )))
        }
        assertThrows(Exception::class.java) {
            SignedFeedPackage.parse(ByteArrayInputStream(zip(
                "manifest.txt" to manifest()
            )))
        }
        assertThrows(Exception::class.java) {
            SignedFeedPackage.parse(ByteArrayInputStream(zip(
                "manifest.txt" to (manifest() + "\n".toByteArray()),
                "signatures.tsv" to database
            )))
        }
    }

    @Test fun parsingDeadlineRejectsUntrustedCompressedFeeds() {
        var now = 0L
        val zipped = zip("manifest.txt" to manifest(), "signatures.tsv" to database)
        val error = assertThrows(Exception::class.java) {
            SignedFeedPackage.parse(ByteArrayInputStream(zipped),
                maxDurationNanos = 10, nanoTime = { now += 11; now })
        }
        assertTrue(error.message.orEmpty().contains("timeout"))
    }

    @Test fun rejectsOversizedEntryBeforeAcceptingPayload() {
        val tooBig = ByteArray(VerifiedSignatureBundle.MAX_DATABASE_BYTES + 1)
        assertThrows(Exception::class.java) {
            SignedFeedPackage.parse(ByteArrayInputStream(zip(
                "manifest.txt" to manifest(), "signatures.tsv" to tooBig
            )))
        }
    }
}
