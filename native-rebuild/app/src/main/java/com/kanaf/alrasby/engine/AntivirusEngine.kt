package com.kanaf.alrasby.engine

import java.io.InputStream

/**
 * Stable contract for antivirus engines. ClamAV/YARA-X are NOT bundled yet.
 * Unavailable or failed engines must never be reported as clean.
 */
interface AntivirusEngine {
    val id: String
    fun scan(openStream: () -> InputStream?, cancelled: () -> Boolean = { false }): Verdict

    sealed interface Verdict {
        data class Detected(val threatName: String) : Verdict
        data object NoKnownMatch : Verdict
        data class Incomplete(val reason: String) : Verdict
    }
}

/** Current bounded SHA-256 scanner adapter, NOT a full antivirus engine. */
class HashSignatureEngine(
    private val signatures: Map<String, String>?,
    private val scanner: StreamScanner = StreamScanner(signatures = signatures ?: emptyMap())
) : AntivirusEngine {
    override val id: String = "kanaf-sha256"
    override fun scan(openStream: () -> InputStream?, cancelled: () -> Boolean): AntivirusEngine.Verdict {
        if (signatures == null) return AntivirusEngine.Verdict.Incomplete("signature-database-unavailable")
        if (cancelled()) return AntivirusEngine.Verdict.Incomplete("cancelled")
        return try {
            val stream = openStream() ?: return AntivirusEngine.Verdict.Incomplete("file-unavailable")
            stream.use {
                when (val result = scanner.scan(it, cancelled)) {
                    is StreamScanner.Result.Completed -> {
                        if (result.signature != null) AntivirusEngine.Verdict.Detected(result.signature)
                        else AntivirusEngine.Verdict.NoKnownMatch
                    }
                    is StreamScanner.Result.Skipped -> AntivirusEngine.Verdict.Incomplete(result.reason)
                }
            }
        } catch (_: Exception) {
            AntivirusEngine.Verdict.Incomplete("read-failed")
        }
    }
}
