package com.kanaf.alrasby.engine

/** Keep a healthy engine available when a worker failure is attributed to YARA-X. */
internal class DeviceNativeScanRecovery(officialAvailable: Boolean) {
    enum class Mode { FULL, LOCAL, PAUSED }

    var mode = if (officialAvailable) Mode.FULL else Mode.LOCAL
        private set
    var failures = 0
        private set
    var yaraPaused = false
        private set

    private fun record(reason: String?, stage: String? = null) {
        when (reason?.removePrefix("INCOMPLETE:")) {
            "scanner-process-disconnected", "scanner-binding-died", "scanner-native-crash",
            "scanner-worker-crash", "scanner-watchdog-timeout", "scanner-timeout",
            "scanner-worker-out-of-memory", "scanner-worker-unresponsive",
            "scanner-ipc-failed", "scanner-process-unavailable", "worker-scan-failed" -> {
                failures++
                if (!yaraPaused && stage == NativeScanProtocol.Stage.YARA_X.name) yaraPaused = true
                else mode = if (mode == Mode.FULL) Mode.LOCAL else Mode.PAUSED
            }
            "clamav-official-device-memory" -> if (mode == Mode.FULL) mode = Mode.LOCAL
        }
    }

    fun scan(
        stopped: () -> Boolean,
        observe: (NativeScannerBridge.Report) -> Unit,
        execute: (allowOfficial: Boolean, allowYara: Boolean) -> NativeScannerBridge.Report
    ): NativeScannerBridge.Report {
        check(mode != Mode.PAUSED)
        fun attempt(): NativeScannerBridge.Report {
            val report = try {
                execute(mode == Mode.FULL, !yaraPaused)
            } catch (_: Exception) {
                NativeScanProtocol.unavailable("scanner-process-unavailable")
            }
            val reason = (report.clamav as? AntivirusEngine.Verdict.Incomplete)?.reason
            record(reason, report.interruptedStage)
            observe(report)
            return report
        }
        val yaraWasPaused = yaraPaused
        val first = attempt()
        return if (!yaraWasPaused && yaraPaused && !stopped()) attempt() else first
    }
}
