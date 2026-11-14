package com.kanaf.alrasby.engine

import android.content.Context
import android.util.AtomicFile
import java.io.File
import java.io.InputStreamReader

/**
 * Local signature repository. Remote updating is DISABLED until an authenticated
 * release pipeline and application-pinned production public key exist.
 *
 * A feed's version, digest and payload are committed in ONE Android AtomicFile.
 * This prevents an interrupted update from pairing different versions and data.
 */
class SignatureRepository(private val context: Context) {
    private val directory: File
        get() = File(context.filesDir, "signature-db").also { check(it.mkdirs() || it.isDirectory) }

    private val verifiedBundle: File get() = File(directory, "verified.bundle")
    private val legacyActive: File get() = File(directory, "active.tsv")
    private val legacyVersion: File get() = File(directory, "version.txt")

    fun load(): Map<String, String> {
        val atomic = AtomicFile(verifiedBundle)
        if (atomic.exists()) {
            // Read + hash-verify the WHOLE bundle before exposing any signature rows.
            val record = atomic.openRead().use { VerifiedSignatureBundle.read(it) }
            val parsed = InputStreamReader(record.bytes.inputStream(), Charsets.UTF_8).use {
                SignatureIndex.parse(it)
            }
            require(parsed.isNotEmpty()) { "Verified database must not be empty" }
            return parsed
        }
        // Previous versions committed these two values separately. Without a signed
        // manifest tying them together, their state cannot be trusted after a crash.
        if (legacyActive.exists() || AtomicFile(legacyVersion).exists()) {
            error("legacy-signature-db-requires-verified-reinstall")
        }
        return context.assets.open("signatures.tsv").use { input ->
            InputStreamReader(input, Charsets.UTF_8).use { SignatureIndex.parse(it) }
        }
    }

    /**
     * Caller MUST supply the application's pinned production key, never a key
     * from the response. There is not yet a network caller or production key.
     * Retaining the legacy version floor prevents rollback during migration.
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
        require(bytes.isNotEmpty() && bytes.size <= VerifiedSignatureBundle.MAX_DATABASE_BYTES) {
            "Database exceeds size limits or is empty"
        }
        val parsed = InputStreamReader(bytes.inputStream(), Charsets.UTF_8).use {
            SignatureIndex.parse(it)
        }
        require(parsed.isNotEmpty()) { "Refusing an empty signature database" }

        val active = AtomicFile(verifiedBundle)
        // Invalid/corrupted active data fails closed: never discard a version
        // floor merely because one copy is unreadable.
        val currentVersion = if (active.exists()) {
            active.openRead().use { VerifiedSignatureBundle.read(it).version }
        } else 0L
        val legacy = AtomicFile(legacyVersion)
        val legacyFloor = if (legacy.exists()) {
            legacy.openRead().reader(Charsets.US_ASCII).use { it.readText().trim().toLong() }
        } else 0L
        VerifiedSignatureBundle.requireNewer(manifest.version, currentVersion, legacyFloor)

        val output = active.startWrite()
        try {
            VerifiedSignatureBundle.write(output, manifest.version, manifest.sha256, bytes)
            active.finishWrite(output)
        } catch (e: Exception) {
            active.failWrite(output)
            throw e
        }
    }
}
