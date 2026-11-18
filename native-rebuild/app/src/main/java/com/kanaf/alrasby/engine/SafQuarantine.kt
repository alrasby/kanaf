package com.kanaf.alrasby.engine

import android.content.Context
import android.net.Uri
import android.provider.DocumentsContract

/**
 * Explicit, consent-based move of ONE SAF document into the encrypted vault.
 * It never quarantines arbitrary app/system files, and a failed provider delete
 * is reported as COPY_ONLY, never as successful isolation.
 */
class SafQuarantine(private val vault: EncryptedVault = EncryptedVault()) {
    sealed interface Outcome {
        data class Moved(val id: String) : Outcome
        data class CopyOnly(val id: String, val reason: String) : Outcome
        data class Failed(val reason: String) : Outcome
    }

    fun isolateSelectedDocument(context: Context, uri: Uri): Outcome {
        if (uri.scheme != "content" || !DocumentsContract.isDocumentUri(context, uri)) {
            return Outcome.Failed("not-a-SAF-document")
        }
        val resolver = context.contentResolver
        val canDelete = try {
            resolver.query(uri, arrayOf(DocumentsContract.Document.COLUMN_FLAGS), null, null, null)
                ?.use { row ->
                    row.moveToFirst() &&
                        row.getInt(0) and DocumentsContract.Document.FLAG_SUPPORTS_DELETE != 0
                } == true
        } catch (_: Exception) { false }
        // Never store an unverified copy as an "isolation" success.
        val baseline = checksum(context, uri)
            ?: return Outcome.Failed("source-unreadable-or-too-large")
        val encrypted = try { vault.store(context, uri) }
            catch (_: Exception) { return Outcome.Failed("encrypted-copy-failed") }
        val copiedDigest = runCatching {
            vault.verifiedPlaintextDigest(context, encrypted.id)
        }.getOrNull()
        if (copiedDigest != baseline) {
            // Preserve the encrypted copy for manual inspection; do NOT delete
            // the source if it changed between reads or verification failed.
            return Outcome.CopyOnly(encrypted.id, "source-or-copy-changed")
        }
        val latest = checksum(context, uri)
        if (latest == null || latest != baseline) {
            return Outcome.CopyOnly(encrypted.id, "source-changed-before-delete")
        }
        if (!canDelete) return Outcome.CopyOnly(encrypted.id, "provider-does-not-support-delete")
        return try {
            if (DocumentsContract.deleteDocument(resolver, uri)) {
                Outcome.Moved(encrypted.id)
            } else {
                Outcome.CopyOnly(encrypted.id, "provider-declined-delete")
            }
        } catch (_: Exception) {
            Outcome.CopyOnly(encrypted.id, "provider-delete-failed")
        }
    }

    private fun checksum(context: Context, uri: Uri): String? {
        val verdict = HashSignatureEngine(emptyMap()).scan({
            context.contentResolver.openInputStream(uri)
        })
        return (verdict as? AntivirusEngine.Verdict.NoKnownMatch)?.sha256
    }
}
