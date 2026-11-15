package com.kanaf.alrasby.engine

/** Honest labels: encrypted copy != source removal. */
internal object QuarantineOutcomeText {
    fun isIsolated(outcome: SafQuarantine.Outcome): Boolean =
        outcome is SafQuarantine.Outcome.Moved

    fun reason(outcome: SafQuarantine.Outcome): String = when (outcome) {
        is SafQuarantine.Outcome.Moved -> "source-deleted-by-document-provider"
        is SafQuarantine.Outcome.CopyOnly -> "copy-only:" + outcome.reason
        is SafQuarantine.Outcome.Failed -> "not-quarantined:" + outcome.reason
    }
}
