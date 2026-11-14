package com.kanaf.alrasby.engine

/** Explainable rule-based evidence fusion; not a trained machine-learning model. */
object ThreatEvidence {
    enum class Severity { CONFIRMED, SUSPICIOUS, INCONCLUSIVE, NO_KNOWN_MATCH }
    data class Assessment(val severity: Severity, val reasons: List<String>)

    fun assess(
        signature: String?,
        apk: ApkStructureInspector.Result?,
        dex: DexHeaderInspector.Result?,
        zip: ZipInspector.Result?
    ): Assessment {
        val reasons = mutableListOf<String>()
        if (signature != null) {
            reasons += "Known threat signature matched"
            return Assessment(Severity.CONFIRMED, reasons)
        }
        var suspicious = false
        var incomplete = false
        if (apk is ApkStructureInspector.Result.Complete && apk.summary.unsafePaths > 0) {
            suspicious = true
            reasons += "Unsafe or duplicate APK paths"
        }
        if (dex is DexHeaderInspector.Result.Complete && dex.summary.invalidHeaders > 0) {
            suspicious = true
            reasons += "Invalid DEX headers"
        }
        if (zip is ZipInspector.Result.Complete && zip.summary.unsafeNames > 0) {
            suspicious = true
            reasons += "Unsafe archive paths"
        }
        if (apk is ApkStructureInspector.Result.Incomplete ||
            dex is DexHeaderInspector.Result.Incomplete ||
            zip is ZipInspector.Result.Incomplete) {
            incomplete = true
            reasons += "Structural analysis incomplete"
        }
        return when {
            suspicious -> Assessment(Severity.SUSPICIOUS, reasons)
            incomplete -> Assessment(Severity.INCONCLUSIVE, reasons)
            else -> Assessment(Severity.NO_KNOWN_MATCH, listOf("No known match; safety not established"))
        }
    }
}
