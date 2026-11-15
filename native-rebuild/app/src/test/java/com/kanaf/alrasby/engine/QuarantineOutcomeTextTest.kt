package com.kanaf.alrasby.engine

import org.junit.Assert.*
import org.junit.Test

class QuarantineOutcomeTextTest {
    @Test fun encryptedCopyAloneIsNeverCalledIsolation() {
        val copy = SafQuarantine.Outcome.CopyOnly("abc", "provider-delete-failed")
        assertFalse(QuarantineOutcomeText.isIsolated(copy))
        assertTrue(QuarantineOutcomeText.reason(copy).startsWith("copy-only:"))
    }

    @Test fun successfulSourceDeletionHasDistinctOutcome() {
        val moved = SafQuarantine.Outcome.Moved("abc")
        assertTrue(QuarantineOutcomeText.isIsolated(moved))
    }

    @Test fun failedEncryptionCannotBecomeIsolation() {
        val failed = SafQuarantine.Outcome.Failed("vault-not-available")
        assertFalse(QuarantineOutcomeText.isIsolated(failed))
    }
}
