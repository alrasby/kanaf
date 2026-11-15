package com.kanaf.alrasby.engine

import android.content.Context
import android.provider.DocumentsContract
import androidx.work.Worker
import androidx.work.WorkerParameters
import java.util.Locale

/**
 * Every 24 h (best-effort): check up to 32 DIRECT child documents of an explicitly
 * SAF-granted directory against the local, bounded SHA-256 index. No full-device
 * privilege, no silent traversal, no unbounded native parsing.
 */
class ScopedFileCheckWorker(context: Context, params: WorkerParameters) :
    Worker(context, params) {
    override fun doWork(): Result {
        if (!ProtectionControl.periodicEnabled(applicationContext)) return Result.success()
        val tree = ProtectionControl.permittedTree(applicationContext)
            ?: return Result.success()
        val permission = applicationContext.contentResolver.persistedUriPermissions.any {
            it.uri == tree && it.isReadPermission
        }
        if (!permission) {
            ProtectionControl.saveResult(applicationContext, "INCOMPLETE: selected folder permission lost")
            ProtectionAlerts.post(applicationContext, 12001,
                "Kanaf scheduled check incomplete", "Selected folder permission is no longer available")
            return Result.success()
        }
        val signatures = runCatching { SignatureRepository(applicationContext).load() }.getOrNull()
        if (signatures == null) {
            ProtectionControl.saveResult(applicationContext, "INCOMPLETE: signature database unavailable")
            return Result.success()
        }
        var checked = 0
        var matches = 0
        var incomplete = 0
        var truncated = false
        try {
            val resolver = applicationContext.contentResolver
            val children = DocumentsContract.buildChildDocumentsUriUsingTree(
                tree, DocumentsContract.getTreeDocumentId(tree)
            )
            resolver.query(children,
                arrayOf(DocumentsContract.Document.COLUMN_DOCUMENT_ID,
                    DocumentsContract.Document.COLUMN_MIME_TYPE,
                    DocumentsContract.Document.COLUMN_SIZE),
                null, null, null)?.use { cursor ->
                val idColumn = cursor.getColumnIndexOrThrow(DocumentsContract.Document.COLUMN_DOCUMENT_ID)
                val typeColumn = cursor.getColumnIndexOrThrow(DocumentsContract.Document.COLUMN_MIME_TYPE)
                val sizeColumn = cursor.getColumnIndexOrThrow(DocumentsContract.Document.COLUMN_SIZE)
                while (!isStopped && cursor.moveToNext()) {
                    if (checked + incomplete >= 32) { truncated = true; break }
                    val mime = cursor.getString(typeColumn)
                    if (mime == DocumentsContract.Document.MIME_TYPE_DIR) continue
                    val size = if (cursor.isNull(sizeColumn)) -1L else cursor.getLong(sizeColumn)
                    if (size > 16L * 1024 * 1024) { incomplete++; continue }
                    val document = DocumentsContract.buildDocumentUriUsingTree(
                        tree, cursor.getString(idColumn)
                    )
                    val verdict = HashSignatureEngine(signatures).scan({
                        resolver.openInputStream(document)
                    }, { isStopped })
                    when (verdict) {
                        is AntivirusEngine.Verdict.Detected -> matches++
                        is AntivirusEngine.Verdict.NoKnownMatch -> checked++
                        is AntivirusEngine.Verdict.Incomplete -> incomplete++
                    }
                }
            } ?: run { incomplete++ }
        } catch (_: Exception) { incomplete++ }
        if (isStopped || !ProtectionControl.periodicEnabled(applicationContext)) return Result.success()
        val message = "Scoped SHA-256: checked=$checked matches=$matches incomplete=$incomplete truncated=$truncated"
        ProtectionControl.saveResult(applicationContext, message)
        if (matches > 0) {
            ProtectionAlerts.post(applicationContext, 12002,
                "Kanaf local signature match", "Review your selected folder in Kanaf. This is not a full antivirus verdict.")
        } else if (incomplete > 0 || truncated) {
            ProtectionAlerts.post(applicationContext, 12003,
                "Kanaf scoped scan incomplete", "Some selected-folder files could not be checked.")
        }
        return Result.success()
    }
}
