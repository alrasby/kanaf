package com.kanaf.alrasby.engine

/**
 * Count attempted files separately from secondary archive checks and unreadable
 * provider directories. No result may be silently promoted to "clean".
 */
class ScopedScanAccounting(private val maximumFiles: Int) {
    init { require(maximumFiles in 1..10_000) }

    enum class Outcome { NO_KNOWN_MATCH, SIGNATURE_MATCH, INCOMPLETE }

    var attemptedFiles = 0
        private set
    var noKnownMatches = 0
        private set
    var signatureMatches = 0
        private set
    var incompleteChecks = 0
        private set
    var structureWarnings = 0
        private set

    val atLimit: Boolean get() = attemptedFiles >= maximumFiles

    fun beginFile(): Boolean {
        if (atLimit) return false
        attemptedFiles++
        return true
    }

    fun record(outcome: Outcome, structuralIncomplete: Boolean = false) {
        when (outcome) {
            Outcome.NO_KNOWN_MATCH -> {
                if (!structuralIncomplete) noKnownMatches++
            }
            Outcome.SIGNATURE_MATCH -> signatureMatches++
            Outcome.INCOMPLETE -> Unit
        }
        if (outcome == Outcome.INCOMPLETE || structuralIncomplete) incompleteChecks++
    }

    fun recordProviderError() { incompleteChecks++ }
    fun recordStructureWarning() { structureWarnings++ }
}
