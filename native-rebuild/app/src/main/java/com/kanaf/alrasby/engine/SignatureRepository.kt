package com.kanaf.alrasby.engine

import android.content.Context
import java.io.File
import java.io.InputStreamReader
import java.security.MessageDigest

/**
 * Crash-safe local signature snapshots. The expected digest MUST be supplied by
 * a separately authenticated manifest; a hash supplied alongside untrusted bytes
 * is not an authenticity guarantee.
 */
class SignatureRepository(private val context: Context) {
    private val directory: File get() = File(context.filesDir, "signature-db").also { it.mkdirs() }
    private val active: File get() = File(directory, "active.tsv")
    private val pending: File get() = File(directory, "pending.tsv")

    fun load(): Map<String, String> {
        if (active.isFile) {
            return active.reader(Charsets.UTF_8).use { SignatureIndex.parse(it) }
        }
        return context.assets.open("signatures.tsv").use { input ->
            InputStreamReader(input, Charsets.UTF_8).use { SignatureIndex.parse(it) }
        }
    }

    /**
     * Only verified, monotonic updates may be installed from remote sources.
     * The public key must be pinned by the app, never taken from the download.
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
        val prefs = context.getSharedPreferences("signature-db", Context.MODE_PRIVATE)
        require(manifest.version > prefs.getLong("highestVersion", 0L)) {
            "Database version rollback rejected"
        }
        installValidated(bytes, manifest.sha256)
        check(prefs.edit().putLong("highestVersion", manifest.version).commit()) {
            "Could not persist signature version"
        }
    }

    private fun installValidated(bytes: ByteArray, expectedSha256: String) {
        require(expectedSha256.matches(Regex("[0-9a-fA-F]{64}"))) { "Invalid digest" }
        require(bytes.size <= 32 * 1024 * 1024) { "Database exceeds limit" }
        val actual = MessageDigest.getInstance("SHA-256").digest(bytes)
            .joinToString("") { "%02x".format(it) }
        require(actual.equals(expectedSha256, ignoreCase = true)) { "Database digest mismatch" }
        SignatureIndex.parse(InputStreamReader(bytes.inputStream(), Charsets.UTF_8))
        pending.outputStream().use { out ->
            out.write(bytes)
            out.fd.sync()
        }
        check(pending.renameTo(active)) { "Atomic signature activation failed" }
    }
}
