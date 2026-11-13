package com.kanaf.alrasby.engine

import org.junit.Assert.*
import org.junit.Test

class EngineConsensusTest {
    private val sha = "a".repeat(64)
    private fun report(id: String, verdict: AntivirusEngine.Verdict) = EngineConsensus.Report(id, verdict)

    @Test fun detectionOverridesIncompleteEngine() {
        val decision = EngineConsensus.evaluate(
            listOf(report("clamav", AntivirusEngine.Verdict.Detected("EICAR-Test", sha))),
            setOf("clamav", "yara-x")
        ) as EngineConsensus.Decision.Threat
        assertEquals(1, decision.detections.size)
        assertEquals("yara-x", decision.incomplete.single().engineId)
    }

    @Test fun missingEngineNeverBecomesNoMatch() {
        val decision = EngineConsensus.evaluate(
            listOf(report("clamav", AntivirusEngine.Verdict.NoKnownMatch(sha))),
            setOf("clamav", "yara-x")
        )
        assertTrue(decision is EngineConsensus.Decision.Inconclusive)
    }

    @Test fun allEnginesMustAgreeOnFileHash() {
        val decision = EngineConsensus.evaluate(
            listOf(report("clamav", AntivirusEngine.Verdict.NoKnownMatch(sha)),
                report("yara-x", AntivirusEngine.Verdict.NoKnownMatch("b".repeat(64)))),
            setOf("clamav", "yara-x")
        )
        assertTrue(decision is EngineConsensus.Decision.Inconclusive)
    }

    @Test fun matchingCompletedEnginesReturnOnlyNoKnownMatch() {
        val decision = EngineConsensus.evaluate(
            listOf(report("clamav", AntivirusEngine.Verdict.NoKnownMatch(sha)),
                report("yara-x", AntivirusEngine.Verdict.NoKnownMatch(sha))),
            setOf("clamav", "yara-x")
        ) as EngineConsensus.Decision.NoKnownMatch
        assertEquals(2, decision.checkedEngines)
    }

    @Test(expected = IllegalArgumentException::class)
    fun duplicateReportsRejected() {
        EngineConsensus.evaluate(
            listOf(report("clamav", AntivirusEngine.Verdict.NoKnownMatch(sha)),
                report("clamav", AntivirusEngine.Verdict.NoKnownMatch(sha))),
            setOf("clamav")
        )
    }
}
