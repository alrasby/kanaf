package com.kanaf.alrasby.engine

import android.content.Context
import com.kanaf.alrasby.BuildConfig
import android.util.AtomicFile
import java.io.File
import java.io.InputStreamReader
import java.io.InputStream
import java.util.Base64

/**
 * Local signature repository. Remote updating is DISABLED until an authenticated
 * release pipeline and application-pinned production public key exist.
 *
 * A feed's version, digest and payload are committed in ONE Android AtomicFile.
 * This prevents an interrupted update from pairing different versions and data.
 */
class SignatureRepository(private val context: Context) {
    companion object {
        // One lock per process ensures simultaneous first-use requests cannot
        // independently install conflicting publisher feed versions.
        private val bootstrapLock = Any()
    }

    /**
     * Production first-run: verify the publisher-signed APK-bundled database
     * against the application-pinned key, then atomically commit it.
     * The built-in debug/test signatures.tsv file is NEVER a production fallback.
     */
    internal fun installBundledIfAbsent(
        source: InputStream, pinnedPublicKey: ByteArray, minVersion: Long
    ): Boolean = synchronized(bootstrapLock) {
        if (hasCommittedState(verifiedBundle)) return@synchronized false
        if (legacyActive.isFile || hasCommittedState(legacyVersion)) {
            error("legacy-signature-db-requires-verified-reinstall")
        }
        val parsed = source.use { SignedFeedPackage.parse(it) }
        require(parsed.manifest.version >= minVersion && minVersion > 0L) {
            "Bundled database below release minimum"
        }
        installVerified(parsed.bytes, parsed.manifest, pinnedPublicKey)
        true
    }
    private val directory: File
        get() = File(context.filesDir, "signature-db").also { check(it.mkdirs() || it.isDirectory) }

    private val verifiedBundle: File get() = File(directory, "verified.bundle")
    private val legacyActive: File get() = File(directory, "active.tsv")
    private val legacyVersion: File get() = File(directory, "version.txt")

    /** Android AtomicFile has no exists(): its legacy .bak also represents committed data.
     * Ignore the .new file; a partially written update is never a committed release. */
    private fun hasCommittedState(file: File): Boolean =
        file.isFile || File(file.path + ".bak").isFile

    fun load(): Map<String, String> {
        if (BuildConfig.KANAF_SIGNATURE_MIN_VERSION > 0L &&
            !hasCommittedState(verifiedBundle)) {
            synchronized(bootstrapLock) {
                if (!hasCommittedState(verifiedBundle) &&
                    !legacyActive.isFile && !hasCommittedState(legacyVersion)) {
                    val encoded = BuildConfig.KANAF_SIGNATURE_PUBLIC_KEY_BASE64
                    check(encoded.isNotBlank()) { "production-feed-key-unavailable" }
                    val pub = Base64.getDecoder().decode(encoded)
                    // No unsigned fallback if asset is missing, corrupt, or
                    // signed by the wrong key. Callers report INCOMPLETE.
                    context.assets.open("production_signatures.zip").use { input ->
                        installBundledIfAbsent(input, pub,
                            BuildConfig.KANAF_SIGNATURE_MIN_VERSION)
                    }
                }
            }
        }
        val atomic = AtomicFile(verifiedBundle)
        if (hasCommittedState(verifiedBundle)) {
            // Read + hash-verify the WHOLE bundle before exposing any signature rows.
            val record = atomic.openRead().use { VerifiedSignatureBundle.read(it) }
            require(record.version >= BuildConfig.KANAF_SIGNATURE_MIN_VERSION) {
                "Installed signature database below binary minimum version"
            }
            val parsed = InputStreamReader(record.bytes.inputStream(), Charsets.UTF_8).use {
                SignatureIndex.parse(it)
            }
            require(parsed.isNotEmpty()) { "Verified database must not be empty" }
            return parsed
        }
        // Previous versions committed these two values separately. Without a signed
        // manifest tying them together, their state cannot be trusted after a crash.
        if (legacyActive.isFile || hasCommittedState(legacyVersion)) {
            error("legacy-signature-db-requires-verified-reinstall")
        }
        require(BuildConfig.KANAF_SIGNATURE_MIN_VERSION == 0L) {
            "Production database unavailable: never fall back to test-only signatures"
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
        require(manifest.version >= BuildConfig.KANAF_SIGNATURE_MIN_VERSION) {
            "Signature database below binary minimum version"
        }
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
        val currentVersion = if (hasCommittedState(verifiedBundle)) {
            active.openRead().use { VerifiedSignatureBundle.read(it).version }
        } else 0L
        val legacy = AtomicFile(legacyVersion)
        val legacyFloor = if (hasCommittedState(legacyVersion)) {
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
