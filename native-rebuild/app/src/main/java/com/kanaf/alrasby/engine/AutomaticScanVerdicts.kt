package com.kanaf.alrasby.engine

/**
 * All reports for one automatic scan must agree on the file's SHA-256.
 * If an input changed between hash and JNI scans, any signature finding
 * is UNCONFIRMED, never a definite malware diagnosis.
 */
object AutomaticScanVerdicts {
    fun evaluate(
        hash: AntivirusEngine.Verdict,
        clamav: AntivirusEngine.Verdict,
        yaraX: AntivirusEngine.Verdict
    ): EngineConsensus.Decision = EngineConsensus.evaluate(
        listOf(
            EngineConsensus.Report("kanaf-sha256", hash),
            EngineConsensus.Report("clamav", clamav),
            EngineConsensus.Report("yara-x", yaraX)
        ),
        setOf("kanaf-sha256", "clamav", "yara-x")
    )
}
