package com.kanaf.alrasby.engine

import java.io.ByteArrayOutputStream
import java.io.IOException
import java.io.InputStream
import java.util.zip.ZipInputStream

/**
 * Strict, bounded .zip with exactly signatures.tsv + manifest.txt.
 * The manifest is three ASCII lines: version, lowercase SHA-256, Base64 RSA
 * signature. The signed payload format is Kanaf-DB-v1\nversion\nsha256\n.
 * The ZIP itself is NOT trusted until SignatureRepository.installVerified.
 */
internal object SignedFeedPackage {
    data class Parsed(val bytes: ByteArray, val manifest: SignedSignatureUpdate.Manifest)
    private const val MAX_META = 4096

    fun parse(source: InputStream): Parsed {
        val payloads = HashMap<String, ByteArray>()
        val limited = object : java.io.FilterInputStream(source) {
            var bytesRead = 0L
            private fun count(n: Int) {
                if (n > 0) {
                    bytesRead += n
                    if (bytesRead > VerifiedSignatureBundle.MAX_DATABASE_BYTES + 16384L) {
                        throw IOException("signed-feed-compressed-limit")
                    }
                }
            }
            override fun read(): Int = super.read().also { if (it >= 0) count(1) }
            override fun read(buffer: ByteArray, off: Int, len: Int): Int =
                `in`.read(buffer, off, len).also { count(it) }
        }
        ZipInputStream(limited).use { archive ->
            while (true) {
                val entry = archive.nextEntry ?: break
                val name = entry.name
                val max = when (name) {
                    "manifest.txt" -> MAX_META
                    "signatures.tsv" -> VerifiedSignatureBundle.MAX_DATABASE_BYTES
                    else -> throw IOException("signed-feed-unexpected-entry")
                }
                if (entry.isDirectory || name in payloads) throw IOException("signed-feed-duplicate-entry")
                val output = ByteArrayOutputStream()
                val buffer = ByteArray(8192)
                while (true) {
                    val n = archive.read(buffer)
                    if (n < 0) break
                    if (n > max - output.size()) throw IOException("signed-feed-uncompressed-limit")
                    if (n > 0) output.write(buffer, 0, n)
                }
                payloads[name] = output.toByteArray()
                archive.closeEntry()
            }
        }
        if (payloads.size != 2 || payloads["signatures.tsv"]?.isEmpty() != false) {
            throw IOException("signed-feed-missing-content")
        }
        val meta = payloads["manifest.txt"]?.toString(Charsets.US_ASCII)
            ?: throw IOException("signed-feed-missing-manifest")
        // Do not accept CRLF, malformed Base64 or ambiguous extra fields.
        val pattern = Regex("([1-9][0-9]*)\\n([0-9a-f]{64})\\n([A-Za-z0-9+/]+={0,2})\\n")
        val parsed = pattern.matchEntire(meta) ?: throw IOException("signed-feed-invalid-manifest")
        val version = parsed.groupValues[1].toLongOrNull()
            ?: throw IOException("signed-feed-invalid-version")
        return Parsed(payloads.getValue("signatures.tsv"),
            SignedSignatureUpdate.Manifest(version, parsed.groupValues[2], parsed.groupValues[3]))
    }
}
