package com.kanaf.alrasby.engine

import org.junit.Assert.*
import org.junit.Test

class AutomaticScanVerdictsTest {
    private val original = "a".repeat(64)
    private val altered = "b".repeat(64)
    private fun noMatch(sha: String) = AntivirusEngine.Verdict.NoKnownMatch(sha)
    private fun match(sha: String) = AntivirusEngine.Verdict.Detected("Eicar-Test-Signature", sha)
    private val unavailable = AntivirusEngine.Verdict.Incomplete("native-unavailable")

    @Test fun conflictingNativeDetectionMustNotBeConfirmed() {
        val outcome = AutomaticScanVerdicts.evaluate(
            noMatch(original), match(altered), noMatch(altered))
        assertTrue(outcome is EngineConsensus.Decision.Inconclusive)
        val incomplete = outcome as EngineConsensus.Decision.Inconclusive
        assertEquals("file-changed-between-engines", incomplete.reason)
        assertEquals(1, incomplete.uncorroboratedDetections.size)
    }

    @Test fun sameDigestHarmlessEicarDetectionIsConfirmed() {
        val result = AutomaticScanVerdicts.evaluate(
            noMatch(original), match(original), match(original))
        assertTrue(result is EngineConsensus.Decision.Threat)
        assertEquals(2, (result as EngineConsensus.Decision.Threat).detections.size)
    }

    @Test fun noKnownMatchRequiresAllThreeReadyOnSameFile() {
        assertTrue(AutomaticScanVerdicts.evaluate(
            noMatch(original), noMatch(original), noMatch(original))
            is EngineConsensus.Decision.NoKnownMatch)
        assertTrue(AutomaticScanVerdicts.evaluate(
            noMatch(original), noMatch(original), unavailable)
            is EngineConsensus.Decision.Inconclusive)
    }

    @Test fun aRealSignatureCanBeReportedWhenAnotherEngineIsUnavailable() {
        val result = AutomaticScanVerdicts.evaluate(
            match(original), unavailable, unavailable)
        assertTrue(result is EngineConsensus.Decision.Threat)
        assertEquals(2, (result as EngineConsensus.Decision.Threat).incomplete.size)
    }

    @Test fun malformedHashOrNoCompletedEngineNeverBecomesClean() {
        assertTrue(AutomaticScanVerdicts.evaluate(
            noMatch("wrong"), unavailable, unavailable)
            is EngineConsensus.Decision.Inconclusive)
        assertTrue(AutomaticScanVerdicts.evaluate(
            unavailable, unavailable, unavailable)
            is EngineConsensus.Decision.Inconclusive)
    }
}
