package com.kanaf.alrasby.engine

import android.content.Context
import android.util.AtomicFile
import java.io.File
import java.io.InputStreamReader
import java.security.MessageDigest

/**
 * Local signature repository. Network updates require an authenticated manifest
 * and an app-pinned public key. The database and its version are activated together.
 */
class SignatureRepository(private val context: Context) {
    private val directory: File get() = File(context.filesDir, "signature-db").also { check(it.mkdirs() || it.isDirectory) }
    private val active: File get() = File(directory, "active.tsv")
    private val metadata: File get() = File(directory, "version.txt")
    private val maxDatabaseBytes = 32 * 1024 * 1024

    fun load(): Map<String, String> {
        if (active.isFile) {
            return active.reader(Charsets.UTF_8).use { SignatureIndex.parse(it) }
        }
        return context.assets.open("signatures.tsv").use { input ->
            InputStreamReader(input, Charsets.UTF_8).use { SignatureIndex.parse(it) }
        }
    }

    /**
     * Never accept the public key from the remote response. A production caller
     * must pin it in the application binary.
     *
     * The version is written before the database to fail closed on interruption:
     * after an interrupted update the app may have an older database but must
     * not accept a rollback update.
     */
    @Synchronized
    fun installVerified(
        bytes: ByteArray,
        manifest: SignedSignatureUpdate.Manifest,
        pinnedPublicKeyDer: ByteArray
    ) {
        require(SignedSignatureUpdate.verify(manifest, pinnedPublicKeyDer)) {
            "Untrusted signature database manifest"
        }
        val highest = if (metadata.isFile) {
            metadata.readText(Charsets.US_ASCII).trim().toLong()
        } else 0L
        require(manifest.version > highest) { "Database version rollback rejected" }
        require(bytes.size <= maxDatabaseBytes) { "Database exceeds limit" }
        val actual = MessageDigest.getInstance("SHA-256").digest(bytes)
            .joinToString("") { "%02x".format(it) }
        require(actual == manifest.sha256) { "Database digest mismatch" }
        InputStreamReader(bytes.inputStream(), Charsets.UTF_8).use { SignatureIndex.parse(it) }

        writeAtomic(metadata, manifest.version.toString().toByteArray(Charsets.US_ASCII))
        writeAtomic(active, bytes)
    }

    private fun writeAtomic(file: File, bytes: ByteArray) {
        val atomic = AtomicFile(file)
        val output = atomic.startWrite()
        try {
            output.write(bytes)
            atomic.finishWrite(output)
        } catch (e: Exception) {
            atomic.failWrite(output)
            throw e
        }
    }
}
