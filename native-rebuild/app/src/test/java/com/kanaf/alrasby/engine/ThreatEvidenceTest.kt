package com.kanaf.alrasby.engine

import org.junit.Assert.*
import org.junit.Test

class ThreatEvidenceTest {
    @Test fun knownSignatureTakesPriority() {
        val result = ThreatEvidence.assess("known", null, null, null)
        assertEquals(ThreatEvidence.Severity.CONFIRMED, result.severity)
    }
    @Test fun invalidDexIsSuspicious() {
        val result = ThreatEvidence.assess(null, null,
            DexHeaderInspector.Result.Complete(DexHeaderInspector.Summary(1, 1, 112)), null)
        assertEquals(ThreatEvidence.Severity.SUSPICIOUS, result.severity)
    }
    @Test fun incompleteAnalysisIsNotClean() {
        val result = ThreatEvidence.assess(null,
            ApkStructureInspector.Result.Incomplete("entry-limit"), null, null)
        assertEquals(ThreatEvidence.Severity.INCONCLUSIVE, result.severity)
    }
    @Test fun noEvidenceDoesNotClaimSafety() {
        val result = ThreatEvidence.assess(null, null, null, null)
        assertEquals(ThreatEvidence.Severity.NO_KNOWN_MATCH, result.severity)
        assertTrue(result.reasons.single().contains("safety not established"))
    }
}
