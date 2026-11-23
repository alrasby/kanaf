package com.kanaf.alrasby.engine

/** Strict, bounded message contract for the separate scanner process. Never treats malformed IPC as clean. */
internal object NativeScanProtocol {
    const val REQUEST_FILE = 1
    const val REQUEST_SELF_TEST = 2
    const val RESPONSE = 3
    /** Debuggable builds only. Forces scanner worker death for instrumentation recovery tests. */
    const val REQUEST_DEBUG_CRASH = 4
    const val RESPONSE_STAGE = 5
    enum class Stage { SELF_TEST, FILE_PREPARATION, CLAMAV_LOCAL, CLAMAV_OFFICIAL, YARA_X }
    const val URI_KEY = "scan_uri"
    const val ALLOW_OFFICIAL_KEY = "allow_official"

    // The first official scan may verify, unpack and compile the full database.
    fun watchdogMs(mode: Int, officialBundled: Boolean): Long =
        if (mode != REQUEST_DEBUG_CRASH && officialBundled) 175_000L else 90_000L

    private val shaPattern = Regex("[0-9a-f]{64}")
    private val keys = listOf("kind", "detail", "sha", "loaded", "rules", "self", "engine", "db")
    val responseKeys: List<String> = listOf("clamav", "yara-x").flatMap { engine ->
        keys.map { "$engine.$it" }
    }

    fun unavailable(reason: String): NativeScannerBridge.Report {
        val safeReason = reason.take(120).ifBlank { "scanner-unavailable" }
        val verdict = AntivirusEngine.Verdict.Incomplete(safeReason)
        return NativeScannerBridge.Report(verdict, verdict, listOf(
            NativeEngineGate("clamav", false, false, false),
            NativeEngineGate("yara-x", false, false, false)
        ))
    }

    fun encode(report: NativeScannerBridge.Report): Map<String, String> {
        val out = HashMap<String, String>(responseKeys.size)
        fun add(engine: String, verdict: AntivirusEngine.Verdict) {
            val root = "$engine."
            when (verdict) {
                is AntivirusEngine.Verdict.Detected -> {
                    out[root + "kind"] = "detected"
                    out[root + "detail"] = verdict.threatName.take(128)
                    out[root + "sha"] = verdict.sha256
                }
                is AntivirusEngine.Verdict.NoKnownMatch -> {
                    out[root + "kind"] = "no-match"
                    out[root + "detail"] = ""
                    out[root + "sha"] = verdict.sha256
                }
                is AntivirusEngine.Verdict.Incomplete -> {
                    out[root + "kind"] = "incomplete"
                    out[root + "detail"] = verdict.reason.take(120)
                    out[root + "sha"] = ""
                }
            }
            val gate = report.gates.find { it.engineId == engine }
            out[root + "loaded"] = if (gate?.libraryLoaded == true) "1" else "0"
            out[root + "rules"] = if (gate?.rulesVerified == true) "1" else "0"
            out[root + "self"] = if (gate?.selfTestPassed == true) "1" else "0"
            out[root + "engine"] = gate?.engineVersion?.take(32).orEmpty()
            out[root + "db"] = gate?.rulesVersion?.take(32).orEmpty()
        }
        add("clamav", report.clamav)
        add("yara-x", report.yaraX)
        return out
    }

    fun decode(fields: Map<String, String>): NativeScannerBridge.Report {
        fun one(name: String): Pair<NativeEngineGate, AntivirusEngine.Verdict> {
            val prefix = "$name."
            fun field(key: String) = fields[prefix + key].orEmpty()
            val gate = NativeEngineGate(
                name,
                libraryLoaded = field("loaded") == "1",
                rulesVerified = field("rules") == "1",
                selfTestPassed = field("self") == "1",
                engineVersion = field("engine").take(32).ifBlank { null },
                rulesVersion = field("db").take(32).ifBlank { null }
            )
            val sha = field("sha")
            val detail = field("detail")
            val verdict: AntivirusEngine.Verdict = when (field("kind")) {
                "detected" -> if (gate.ready && shaPattern.matches(sha) &&
                    detail.isNotBlank() && detail.length <= 128) {
                    AntivirusEngine.Verdict.Detected(detail, sha)
                } else AntivirusEngine.Verdict.Incomplete("invalid-native-result")
                "no-match" -> if (gate.ready && shaPattern.matches(sha)) {
                    AntivirusEngine.Verdict.NoKnownMatch(sha)
                } else AntivirusEngine.Verdict.Incomplete("invalid-native-result")
                "incomplete" -> AntivirusEngine.Verdict.Incomplete(detail.take(120).ifBlank {
                    "native-scan-incomplete"
                })
                else -> AntivirusEngine.Verdict.Incomplete("invalid-native-result")
            }
            return gate to verdict
        }
        val clam = one("clamav")
        val yara = one("yara-x")
        return NativeScannerBridge.Report(clam.second, yara.second, listOf(clam.first, yara.first))
    }
}
