package com.kanaf.alrasby.engine

import org.junit.Assert.*
import org.junit.Test

class ScopedScanAccountingTest {
    @Test fun fileLimitCountsAttemptsNotOutcomesOrArchiveWarnings() {
        val ledger = ScopedScanAccounting(2)
        assertTrue(ledger.beginFile())
        ledger.record(ScopedScanAccounting.Outcome.SIGNATURE_MATCH, structuralIncomplete = true)
        ledger.recordStructureWarning()
        ledger.recordProviderError()
        assertTrue(ledger.beginFile())
        ledger.record(ScopedScanAccounting.Outcome.NO_KNOWN_MATCH)
        assertFalse(ledger.beginFile())
        assertEquals(2, ledger.attemptedFiles)
        assertEquals(1, ledger.signatureMatches)
        assertEquals(1, ledger.noKnownMatches)
        assertEquals(2, ledger.incompleteChecks)
        assertEquals(1, ledger.structureWarnings)
        assertTrue(ledger.atLimit)
    }

    @Test fun structuralFailureDoesNotCountAsCompletedNoMatch() {
        val ledger = ScopedScanAccounting(1)
        assertTrue(ledger.beginFile())
        ledger.record(ScopedScanAccounting.Outcome.NO_KNOWN_MATCH, structuralIncomplete = true)
        assertEquals(0, ledger.noKnownMatches)
        assertEquals(1, ledger.incompleteChecks)
        assertFalse(ledger.beginFile())
    }

    @Test fun incompleteEngineIsNotCleanAndCannotConsumeExtraSlots() {
        val ledger = ScopedScanAccounting(1)
        assertTrue(ledger.beginFile())
        ledger.record(ScopedScanAccounting.Outcome.INCOMPLETE)
        assertFalse(ledger.beginFile())
        assertEquals(0, ledger.noKnownMatches)
        assertEquals(0, ledger.signatureMatches)
        assertEquals(1, ledger.incompleteChecks)
    }

    @Test fun invalidFileLimitIsRejected() {
        assertThrows(IllegalArgumentException::class.java) { ScopedScanAccounting(0) }
        assertThrows(IllegalArgumentException::class.java) { ScopedScanAccounting(10_001) }
    }
}
