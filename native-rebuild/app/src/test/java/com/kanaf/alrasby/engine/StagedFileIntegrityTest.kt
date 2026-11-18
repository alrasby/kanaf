package com.kanaf.alrasby.engine

import java.io.File
import java.nio.file.Files
import java.security.MessageDigest
import org.junit.Assert.*
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

class StagedFileIntegrityTest {
    @get:Rule val folder = TemporaryFolder()
    private fun digest(bytes: ByteArray): String =
        MessageDigest.getInstance("SHA-256").digest(bytes)
            .joinToString("") { "%02x".format(it.toInt() and 0xff) }

    @Test fun exactSnapshotAndSealingSucceed() {
        val file = folder.newFile("staged.bin")
        val bytes = "test-content".toByteArray()
        file.writeBytes(bytes)
        assertTrue(StagedFileIntegrity.verify(file, digest(bytes), bytes.size.toLong()))
        assertTrue(StagedFileIntegrity.seal(file))
        assertTrue(StagedFileIntegrity.verify(file, digest(bytes), bytes.size.toLong()))
    }

    @Test fun changedBytesOfSameLengthAreRejected() {
        val file = folder.newFile("changed.bin")
        val before = "abcd".toByteArray()
        file.writeBytes(before)
        val hash = digest(before)
        file.writeText("abce")
        assertFalse(StagedFileIntegrity.verify(file, hash, before.size.toLong()))
    }

    @Test fun changedLengthIsRejected() {
        val file = folder.newFile("short.bin")
        file.writeText("abc")
        assertFalse(StagedFileIntegrity.verify(file, digest("abc".toByteArray()), 4))
        assertFalse(StagedFileIntegrity.verify(file, digest("abc".toByteArray()), 2))
    }

    @Test fun sizeLimitAndInvalidHashFailClosed() {
        val file = folder.newFile("limited.bin")
        file.writeText("abc")
        assertFalse(StagedFileIntegrity.verify(file, digest("abc".toByteArray()), 3, 2))
        assertFalse(StagedFileIntegrity.verify(file, "invalid", 3))
        assertFalse(StagedFileIntegrity.verify(file, digest("abc".toByteArray()), -1))
        assertFalse(StagedFileIntegrity.verify(file, digest("abc".toByteArray()), 3, 0))
    }

    @Test fun missingFileAndSymlinkAreRejected() {
        val target = folder.newFile("target.bin")
        target.writeText("abc")
        val hash = digest("abc".toByteArray())
        assertFalse(StagedFileIntegrity.verify(File(folder.root, "missing.bin"), hash, 3))
        val link = File(folder.root, "symlink.bin")
        Files.createSymbolicLink(link.toPath(), target.toPath())
        assertFalse(StagedFileIntegrity.verify(link, hash, 3))
        assertFalse(StagedFileIntegrity.seal(link))
    }

    @Test fun emptySnapshotIsAllowedWithItsExactDigest() {
        val file = folder.newFile("empty.bin")
        assertTrue(StagedFileIntegrity.verify(file, digest(byteArrayOf()), 0))
    }
}
