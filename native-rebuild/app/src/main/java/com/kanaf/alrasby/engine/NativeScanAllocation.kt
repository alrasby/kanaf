package com.kanaf.alrasby.engine

/** Native checks are bounded ATTEMPTS, never assumed successful findings.
 * Reserve capacity for user-stored APKs/archives instead of exhausting it
 * on installed apps during the initial package-enumeration phase.
 */
class NativeScanAllocation(private val total: Int, sharedEnabled: Boolean) {
    init { require(total >= 0) }
    private val installedLimit = if (sharedEnabled) total / 2 else total
    private val sharedOtherLimit = if (sharedEnabled) (total - installedLimit) / 2 else 0
    private var installed = 0
    private var other = 0
    private var archived = 0
    val totalReserved: Int get() = installed + other + archived
    val installedReserved: Int get() = installed
    val sharedReserved: Int get() = other + archived
    fun reserve(installedApp: Boolean, sharedArchive: Boolean): Boolean {
        if (totalReserved >= total) return false
        return if (installedApp) {
            if (installed >= installedLimit) false
            else { installed++; true }
        } else if (sharedArchive) {
            archived++
            true
        } else {
            if (other >= sharedOtherLimit) false
            else { other++; true }
        }
    }
}
