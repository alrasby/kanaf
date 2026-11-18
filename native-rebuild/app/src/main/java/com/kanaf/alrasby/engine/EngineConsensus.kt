package com.kanaf.alrasby.engine

/**
 * Aggregate scan verdicts only for one file snapshot. A confirmed detection
 * beats unavailable engines, but never verified disagreement on file SHA-256.
 */
object EngineConsensus {
    data class Report(val engineId: String, val verdict: AntivirusEngine.Verdict)
    sealed interface Decision {
        data class Threat(val detections: List<Report>, val incomplete: List<Report>) : Decision
        data class NoKnownMatch(val checkedEngines: Int, val sha256: String) : Decision
        data class Inconclusive(
            val incomplete: List<Report>,
            val checkedEngines: Int,
            val reason: String = "scan-incomplete",
            // Suspicious findings remain visible, but were not confirmed on one snapshot.
            val uncorroboratedDetections: List<Report> = emptyList()
        ) : Decision
    }
    private val validHash = Regex("[0-9a-f]{64}")

    fun evaluate(reports: List<Report>, expectedEngines: Set<String>): Decision {
        require(expectedEngines.isNotEmpty())
        require(reports.map { it.engineId }.distinct().size == reports.size) { "Duplicate engine report" }
        require(reports.all { it.engineId in expectedEngines }) { "Unexpected engine" }

        val observed = reports.associateBy { it.engineId }
        val missing = (expectedEngines - observed.keys).sorted().map {
            Report(it, AntivirusEngine.Verdict.Incomplete("engine-not-run"))
        }
        // Discard malformed hashes/names from any engine instead of accepting
        // a guessed detection or an unsupported clean-like verdict.
        val all = (reports + missing).map { item ->
            val trustworthy = when (val v = item.verdict) {
                is AntivirusEngine.Verdict.Detected ->
                    v.threatName.isNotBlank() && validHash.matches(v.sha256)
                is AntivirusEngine.Verdict.NoKnownMatch -> validHash.matches(v.sha256)
                is AntivirusEngine.Verdict.Incomplete -> true
            }
            if (trustworthy) item else Report(
                item.engineId, AntivirusEngine.Verdict.Incomplete("invalid-engine-result")
            )
        }
        val detected = all.filter { it.verdict is AntivirusEngine.Verdict.Detected }
        val incomplete = all.filter { it.verdict is AntivirusEngine.Verdict.Incomplete }
        val hashes = all.mapNotNull {
            when (val v = it.verdict) {
                is AntivirusEngine.Verdict.Detected -> v.sha256
                is AntivirusEngine.Verdict.NoKnownMatch -> v.sha256
                is AntivirusEngine.Verdict.Incomplete -> null
            }
        }
        // Distinct hashes imply a file changed between independent SAF reads.
        // No confirmed verdict can be assigned to the user's current file.
        if (hashes.distinct().size > 1) {
            return Decision.Inconclusive(
                incomplete = incomplete, checkedEngines = hashes.size,
                reason = "file-changed-between-engines",
                uncorroboratedDetections = detected
            )
        }
        if (detected.isNotEmpty()) return Decision.Threat(detected, incomplete)
        if (incomplete.isNotEmpty() || hashes.isEmpty()) {
            return Decision.Inconclusive(incomplete, hashes.size)
        }
        return Decision.NoKnownMatch(hashes.size, hashes.first())
    }
}
