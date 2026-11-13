package com.kanaf.alrasby.engine

/**
 * Aggregates independent scanner outcomes without converting missing coverage
 * into a clean verdict. A detection always wins over incomplete/negative scans.
 */
object EngineConsensus {
    data class Report(val engineId: String, val verdict: AntivirusEngine.Verdict)
    sealed interface Decision {
        data class Threat(val detections: List<Report>, val incomplete: List<Report>) : Decision
        data class NoKnownMatch(val checkedEngines: Int, val sha256: String) : Decision
        data class Inconclusive(val incomplete: List<Report>, val checkedEngines: Int) : Decision
    }

    fun evaluate(reports: List<Report>, expectedEngines: Set<String>): Decision {
        require(expectedEngines.isNotEmpty())
        require(reports.map { it.engineId }.distinct().size == reports.size) { "Duplicate engine report" }
        require(reports.all { it.engineId in expectedEngines }) { "Unexpected engine" }

        val observed = reports.associateBy { it.engineId }
        val missing = (expectedEngines - observed.keys).sorted().map {
            Report(it, AntivirusEngine.Verdict.Incomplete("engine-not-run"))
        }
        val all = reports + missing
        val detections = all.filter { it.verdict is AntivirusEngine.Verdict.Detected }
        val incomplete = all.filter { it.verdict is AntivirusEngine.Verdict.Incomplete }
        if (detections.isNotEmpty()) return Decision.Threat(detections, incomplete)
        val negatives = all.mapNotNull { (it.verdict as? AntivirusEngine.Verdict.NoKnownMatch)?.sha256 }
        if (incomplete.isNotEmpty() || negatives.distinct().size > 1)
            return Decision.Inconclusive(incomplete, negatives.size)
        return Decision.NoKnownMatch(negatives.size, negatives.first())
    }
}
