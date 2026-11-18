package com.kanaf.alrasby.engine

import org.junit.Assert.*
import org.junit.Test

class TrustJourneyTest {
    private fun assessment(severity: ThreatEvidence.Severity) =
        ThreatEvidence.Assessment(severity, emptyList())

    @Test fun confirmedMatchStopsInstallation() {
        val card = TrustJourney.build(assessment(ThreatEvidence.Severity.CONFIRMED), true, true)
        assertEquals(TrustJourney.Action.STOP_AND_VERIFY, card.action)
    }
    @Test fun structuralSuspicionRequestsReview() {
        val card = TrustJourney.build(assessment(ThreatEvidence.Severity.SUSPICIOUS), true, true)
        assertEquals(TrustJourney.Action.REVIEW_BEFORE_INSTALLING, card.action)
    }
    @Test fun skippedScanNeverLooksClean() {
        val card = TrustJourney.build(assessment(ThreatEvidence.Severity.NO_KNOWN_MATCH), false, true)
        assertEquals(TrustJourney.Action.RETRY_SCAN, card.action)
    }
    @Test fun missingDatabaseNeverLooksClean() {
        val card = TrustJourney.build(assessment(ThreatEvidence.Severity.NO_KNOWN_MATCH), true, false)
        assertEquals(TrustJourney.Action.RETRY_SCAN, card.action)
    }
    @Test fun noMatchStillRecommendsSourceVerification() {
        val card = TrustJourney.build(assessment(ThreatEvidence.Severity.NO_KNOWN_MATCH), true, true)
        assertEquals(TrustJourney.Action.VERIFY_SOURCE, card.action)
        assertTrue(card.explanation.contains("غير مكتشفة"))
    }
}
