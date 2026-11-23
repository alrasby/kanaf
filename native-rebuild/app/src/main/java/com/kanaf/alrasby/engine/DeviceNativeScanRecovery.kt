package com.kanaf.alrasby.engine

/** After a full-engine failure, allow local checks until the worker fails again. */
internal class DeviceNativeScanRecovery(officialAvailable: Boolean) {
    enum class Mode { FULL, LOCAL, PAUSED }

    var mode = if (officialAvailable) Mode.FULL else Mode.LOCAL
        private set
    var failures = 0
        private set

    fun record(reason: String?) {
        when (reason?.removePrefix("INCOMPLETE:")) {
            "scanner-process-disconnected", "scanner-binding-died", "scanner-native-crash",
            "scanner-worker-crash", "scanner-watchdog-timeout", "scanner-timeout",
            "scanner-worker-out-of-memory", "scanner-worker-unresponsive",
            "scanner-ipc-failed", "scanner-process-unavailable", "worker-scan-failed" -> {
                failures++
                mode = if (mode == Mode.FULL) Mode.LOCAL else Mode.PAUSED
            }
            "clamav-official-device-memory" -> if (mode == Mode.FULL) mode = Mode.LOCAL
        }
    }
}
