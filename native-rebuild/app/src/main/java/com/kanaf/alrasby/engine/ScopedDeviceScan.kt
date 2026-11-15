package com.kanaf.alrasby.engine

import android.content.Context
import android.net.Uri
import android.os.SystemClock
import android.provider.DocumentsContract
import java.util.ArrayDeque

/**
 * An explicitly user-selected SAF tree only. Never deletes/quarantines a source.
 * Recursive and bounded: a file is not certified clean if any scan gate is missing.
 */
class ScopedDeviceScan {
    data class Finding(val name: String, val label: String)
    data class Report(
        val scanned: Int,
        val matched: Int,
        val incomplete: Int,
        val structuralWarnings: Int,
        val truncated: Boolean,
        val findings: List<Finding>
    )

    companion object {
        const val MAX_FILES = 24
        const val MAX_DIRECTORIES = 32
        const val MAX_DEPTH = 5
        const val MAX_FILE_BYTES = 16L * 1024 * 1024
        const val MAX_DURATION_MS = 120_000L
    }

    /** Provider grants are scoped by Android; no MANAGE_EXTERNAL_STORAGE needed. */
    fun scan(context: Context, tree: Uri, cancelled: () -> Boolean = { false }): Report {
        require(tree.scheme == "content") { "Only Android SAF content trees are supported" }
        val start = SystemClock.elapsedRealtime()
        val resolver = context.contentResolver
        val signatures = runCatching { SignatureRepository(context).load() }.getOrNull()
        val roots = ArrayDeque<Pair<String, Int>>()
        roots.add(DocumentsContract.getTreeDocumentId(tree) to 0)
        var directories = 0
        var scanned = 0
        var matched = 0
        var incomplete = 0
        var structuralWarnings = 0
        var truncated = false
        val findings = ArrayList<Finding>()
        fun expired(): Boolean = cancelled() ||
            SystemClock.elapsedRealtime() - start >= MAX_DURATION_MS
        while (roots.isNotEmpty()) {
            if (expired() || directories >= MAX_DIRECTORIES) {
                truncated = true
                break
            }
            val (parent, depth) = roots.removeFirst()
            directories++
            try {
                val children = DocumentsContract.buildChildDocumentsUriUsingTree(tree, parent)
                val columns = arrayOf(
                    DocumentsContract.Document.COLUMN_DOCUMENT_ID,
                    DocumentsContract.Document.COLUMN_DISPLAY_NAME,
                    DocumentsContract.Document.COLUMN_MIME_TYPE,
                    DocumentsContract.Document.COLUMN_SIZE
                )
                val cursor = resolver.query(children, columns, null, null, null)
                if (cursor == null) {
                    incomplete++
                    continue
                }
                cursor.use { records ->
                    val idCol = records.getColumnIndexOrThrow(columns[0])
                    val nameCol = records.getColumnIndexOrThrow(columns[1])
                    val typeCol = records.getColumnIndexOrThrow(columns[2])
                    val sizeCol = records.getColumnIndexOrThrow(columns[3])
                    while (records.moveToNext()) {
                        if (expired() || scanned + matched + incomplete >= MAX_FILES) {
                            truncated = true
                            break
                        }
                        val id = records.getString(idCol)
                        if (id.isNullOrBlank()) {
                            incomplete++
                            continue
                        }
                        val mime = records.getString(typeCol).orEmpty()
                        if (mime == DocumentsContract.Document.MIME_TYPE_DIR) {
                            if (depth >= MAX_DEPTH || roots.size >= MAX_DIRECTORIES) {
                                truncated = true
                            } else roots.addLast(id to (depth + 1))
                            continue
                        }
                        val display = records.getString(nameCol).orEmpty()
                            .replace('\n', ' ').replace('\r', ' ').take(90)
                            .ifBlank { "unnamed-document" }
                        val size = if (records.isNull(sizeCol)) -1L else records.getLong(sizeCol)
                        if (size > MAX_FILE_BYTES) {
                            incomplete++
                            continue
                        }
                        val uri = DocumentsContract.buildDocumentUriUsingTree(tree, id)
                        try {
                            val hashVerdict = HashSignatureEngine(
                                signatures,
                                StreamScanner(maxBytes = MAX_FILE_BYTES,
                                    signatures = signatures ?: emptyMap())
                            ).scan({ resolver.openInputStream(uri) }, ::expired)
                            if (hashVerdict is AntivirusEngine.Verdict.Incomplete) {
                                incomplete++
                                continue
                            }
                            // Execute both genuine native engines through the worker IPC;
                            // they may be INCOMPLETE until their real self-tests pass.
                            val native = NativeScannerBridge.scan(context, uri)
                            val consensus = EngineConsensus.evaluate(listOf(
                                EngineConsensus.Report("kanaf-sha256", hashVerdict),
                                EngineConsensus.Report("clamav", native.clamav),
                                EngineConsensus.Report("yara-x", native.yaraX)
                            ), setOf("kanaf-sha256", "clamav", "yara-x"))
                            when (consensus) {
                                is EngineConsensus.Decision.Threat -> {
                                    matched++
                                    val label = (consensus.detections.first().verdict
                                        as AntivirusEngine.Verdict.Detected).threatName
                                    if (findings.size < 12) findings.add(Finding(display, label))
                                }
                                is EngineConsensus.Decision.NoKnownMatch -> scanned++
                                is EngineConsensus.Decision.Inconclusive -> incomplete++
                            }
                            if (display.endsWith(".apk", true) ||
                                display.endsWith(".zip", true) ||
                                mime == "application/zip") {
                                val structural = resolver.openInputStream(uri)?.use {
                                    ZipInspector().inspect(it)
                                }
                                when (structural) {
                                    is ZipInspector.Result.Complete -> {
                                        if (structural.summary.unsafeNames > 0) {
                                            structuralWarnings++
                                            if (findings.size < 12) findings.add(
                                                Finding(display, "Structural.UnsafeArchivePaths"))
                                        }
                                    }
                                    else -> incomplete++
                                }
                            }
                        } catch (_: Exception) { incomplete++ }
                    }
                }
            } catch (_: Exception) { incomplete++ }
        }
        return Report(scanned, matched, incomplete, structuralWarnings,
            truncated || roots.isNotEmpty() || expired(), findings)
    }
}
