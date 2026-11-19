package com.kanaf.alrasby.engine

import android.content.Context
import android.net.Uri
import android.os.SystemClock
import android.provider.DocumentsContract
import java.util.ArrayDeque

/**
 * On-demand scan of ONE Android user-authorized SAF tree. No deletion,
 * quarantine, broad storage privilege or guarantee of full-device coverage.
 * JNI scans remain subject to their independent fail-closed self-test gates.
 */
class ScopedDeviceScan {
    enum class FindingKind { SIGNATURE_MATCH, STRUCTURAL_WARNING }
    data class Finding(val name: String, val label: String, val kind: FindingKind)
    data class Report(
        val attempted: Int,
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
        val MAX_FILE_BYTES get() = NativeScannerBridge.inputLimit
        const val MAX_DURATION_MS = 120_000L
    }

    fun scan(context: Context, tree: Uri, cancelled: () -> Boolean = { false }): Report {
        require(tree.scheme == "content") { "Only Android SAF content trees are supported" }
        val start = SystemClock.elapsedRealtime()
        val resolver = context.contentResolver
        val signatures = runCatching { SignatureRepository(context).load() }.getOrNull()
        val roots = ArrayDeque<Pair<String, Int>>()
        roots.add(DocumentsContract.getTreeDocumentId(tree) to 0)
        val accounting = ScopedScanAccounting(MAX_FILES)
        var directories = 0
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
                    accounting.recordProviderError()
                    continue
                }
                cursor.use { records ->
                    val idCol = records.getColumnIndexOrThrow(columns[0])
                    val nameCol = records.getColumnIndexOrThrow(columns[1])
                    val typeCol = records.getColumnIndexOrThrow(columns[2])
                    val sizeCol = records.getColumnIndexOrThrow(columns[3])
                    while (records.moveToNext()) {
                        if (expired() || accounting.atLimit) {
                            truncated = true
                            break
                        }
                        val id = records.getString(idCol)
                        if (id.isNullOrBlank()) {
                            accounting.recordProviderError()
                            continue
                        }
                        val mime = records.getString(typeCol).orEmpty()
                        if (mime == DocumentsContract.Document.MIME_TYPE_DIR) {
                            if (depth >= MAX_DEPTH || roots.size >= MAX_DIRECTORIES) {
                                truncated = true
                            } else {
                                roots.addLast(id to (depth + 1))
                            }
                            continue
                        }
                        // Count file slots ONCE, even if the archive check also
                        // reports an incomplete condition or a structural warning.
                        if (!accounting.beginFile()) {
                            truncated = true
                            break
                        }
                        val display = records.getString(nameCol).orEmpty()
                            .replace('\n', ' ').replace('\r', ' ').take(90)
                            .ifBlank { "unnamed-document" }
                        val size = if (records.isNull(sizeCol)) -1L else records.getLong(sizeCol)
                        if (size > MAX_FILE_BYTES) {
                            accounting.record(ScopedScanAccounting.Outcome.INCOMPLETE)
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
                                accounting.record(ScopedScanAccounting.Outcome.INCOMPLETE)
                                continue
                            }
                            val native = NativeScannerBridge.scan(context, uri)
                            val consensus = EngineConsensus.evaluate(listOf(
                                EngineConsensus.Report("kanaf-sha256", hashVerdict),
                                EngineConsensus.Report("clamav", native.clamav),
                                EngineConsensus.Report("yara-x", native.yaraX)
                            ), setOf("kanaf-sha256", "clamav", "yara-x"))
                            val outcome = when (consensus) {
                                is EngineConsensus.Decision.Threat -> {
                                    val label = (consensus.detections.first().verdict
                                        as AntivirusEngine.Verdict.Detected).threatName
                                    if (findings.size < 12) findings.add(
                                        Finding(display, label, FindingKind.SIGNATURE_MATCH))
                                    ScopedScanAccounting.Outcome.SIGNATURE_MATCH
                                }
                                is EngineConsensus.Decision.NoKnownMatch ->
                                    ScopedScanAccounting.Outcome.NO_KNOWN_MATCH
                                is EngineConsensus.Decision.Inconclusive ->
                                    ScopedScanAccounting.Outcome.INCOMPLETE
                            }
                            var structuralIncomplete = false
                            if (display.endsWith(".apk", true) ||
                                display.endsWith(".zip", true) ||
                                mime == "application/zip" ||
                                mime == "application/vnd.android.package-archive") {
                                val structural = resolver.openInputStream(uri)?.use {
                                    ZipInspector().inspect(it)
                                }
                                when (structural) {
                                    is ZipInspector.Result.Complete -> {
                                        if (structural.summary.unsafeNames > 0) {
                                            accounting.recordStructureWarning()
                                            if (findings.size < 12) findings.add(Finding(
                                                display, "Structural.UnsafeArchivePaths",
                                                FindingKind.STRUCTURAL_WARNING))
                                        }
                                    }
                                    else -> structuralIncomplete = true
                                }
                            }
                            accounting.record(outcome, structuralIncomplete)
                        } catch (_: Exception) {
                            accounting.record(ScopedScanAccounting.Outcome.INCOMPLETE)
                        }
                    }
                }
            } catch (_: Exception) {
                accounting.recordProviderError()
            }
        }
        return Report(
            accounting.attemptedFiles,
            accounting.noKnownMatches, accounting.signatureMatches,
            accounting.incompleteChecks, accounting.structureWarnings,
            truncated || roots.isNotEmpty() || expired(), findings
        )
    }
}
