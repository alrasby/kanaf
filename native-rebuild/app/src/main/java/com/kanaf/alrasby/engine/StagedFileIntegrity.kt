package com.kanaf.alrasby.engine

import java.io.File
import java.security.MessageDigest

/** Verify the exact immutable private-cache snapshot used by the native engines.
 * Any truncation, modification, symlink or I/O error fails closed. */
internal object StagedFileIntegrity {
    private val hashPattern = Regex("[0-9a-f]{64}")

    fun seal(file: File): Boolean =
        file.isFile && !java.nio.file.Files.isSymbolicLink(file.toPath()) &&
            file.setReadOnly() && file.canRead() && !file.canWrite()

    fun verify(file: File, sha256: String, bytesExpected: Long, maxBytes: Long = 16L * 1024 * 1024): Boolean {
        if (!hashPattern.matches(sha256) || bytesExpected < 0 ||
            maxBytes <= 0 || bytesExpected > maxBytes) return false
        return try {
            if (!file.isFile || java.nio.file.Files.isSymbolicLink(file.toPath()) ||
                file.length() != bytesExpected) return false
            val digest = MessageDigest.getInstance("SHA-256")
            var count = 0L
            file.inputStream().use { source ->
                val buffer = ByteArray(64 * 1024)
                while (true) {
                    val n = source.read(buffer)
                    if (n < 0) break
                    if (n == 0 || n.toLong() > maxBytes - count) return false
                    digest.update(buffer, 0, n)
                    count += n
                }
            }
            count == bytesExpected && digest.digest().joinToString("") {
                "%02x".format(it.toInt() and 0xff)
            } == sha256 && file.length() == bytesExpected
        } catch (_: Exception) {
            false
        }
    }
}
