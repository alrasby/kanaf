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


    @Test fun detectionAndNegativeWithDifferentDigestsRequireRescan() {
        val decision = EngineConsensus.evaluate(
            listOf(report("clamav", AntivirusEngine.Verdict.Detected("EICAR", sha)),
                report("kanaf-sha256", AntivirusEngine.Verdict.NoKnownMatch("b".repeat(64)))),
            setOf("clamav", "kanaf-sha256")
        ) as EngineConsensus.Decision.Inconclusive
        assertEquals("file-changed-between-engines", decision.reason)
        assertEquals(2, decision.checkedEngines)
        assertEquals("clamav", decision.uncorroboratedDetections.single().engineId)
    }

    @Test fun detectionsOnTwoDifferentFileVersionsCannotBeConfirmed() {
        val decision = EngineConsensus.evaluate(
            listOf(report("clamav", AntivirusEngine.Verdict.Detected("EICAR", sha)),
                report("yara-x", AntivirusEngine.Verdict.Detected("EICAR", "b".repeat(64)))),
            setOf("clamav", "yara-x")
        ) as EngineConsensus.Decision.Inconclusive
        assertEquals("file-changed-between-engines", decision.reason)
        assertEquals(2, decision.uncorroboratedDetections.size)
    }

    @Test fun validDetectionStillOverridesAnUnavailableEngine() {
        val result = EngineConsensus.evaluate(
            listOf(report("clamav", AntivirusEngine.Verdict.Detected("EICAR", sha))),
            setOf("clamav", "yara-x")
        )
        assertTrue(result is EngineConsensus.Decision.Threat)
    }

    @Test fun invalidDigestCanNeverReturnNoKnownMatch() {
        val decision = EngineConsensus.evaluate(
            listOf(report("clamav", AntivirusEngine.Verdict.NoKnownMatch("broken"))),
            setOf("clamav")
        ) as EngineConsensus.Decision.Inconclusive
        assertEquals("invalid-engine-result",
            (decision.incomplete.single().verdict as AntivirusEngine.Verdict.Incomplete).reason)
        assertEquals(0, decision.checkedEngines)
    }

    @Test fun malformedDetectionDigestCannotBeConfirmed() {
        assertTrue(EngineConsensus.evaluate(
            listOf(report("clamav", AntivirusEngine.Verdict.Detected("EICAR", "bad"))),
            setOf("clamav")
        ) is EngineConsensus.Decision.Inconclusive)
    }

    @Test fun emptyThreatNameCannotBeConfirmed() {
        assertTrue(EngineConsensus.evaluate(
            listOf(report("clamav", AntivirusEngine.Verdict.Detected("  ", sha))),
            setOf("clamav")
        ) is EngineConsensus.Decision.Inconclusive)
    }

    @Test fun allMissingEnginesNeverCrashOnEmptyHashes() {
        val decision = EngineConsensus.evaluate(emptyList(), setOf("clamav", "yara-x"))
            as EngineConsensus.Decision.Inconclusive
        assertEquals(0, decision.checkedEngines)
        assertEquals(2, decision.incomplete.size)
    }

    @Test fun consistentDetectionAndNegativesReferToTheSameFile() {
        val result = EngineConsensus.evaluate(
            listOf(report("clamav", AntivirusEngine.Verdict.Detected("EICAR", sha)),
                report("yara-x", AntivirusEngine.Verdict.NoKnownMatch(sha)),
                report("kanaf-sha256", AntivirusEngine.Verdict.NoKnownMatch(sha))),
            setOf("clamav", "yara-x", "kanaf-sha256")
        )
        assertTrue(result is EngineConsensus.Decision.Threat)
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
