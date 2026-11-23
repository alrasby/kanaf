package com.kanaf.alrasby.engine

import org.junit.Assert.assertEquals
import org.junit.Test

class DeviceNativeScanRecoveryTest {
    private fun DeviceNativeScanRecovery.receive(reason: String) =
        scan(stopped = { false }, observe = {}) { _, _ -> NativeScanProtocol.unavailable(reason) }

    @Test fun processFailuresAllowOneFallbackBeforePausing() {
        val recovery = DeviceNativeScanRecovery(officialAvailable = true)
        recovery.receive("INCOMPLETE:clamav-scan-time-limit")
        assertEquals(DeviceNativeScanRecovery.Mode.FULL, recovery.mode)
        assertEquals(0, recovery.failures)

        recovery.receive("scanner-native-crash")
        assertEquals(DeviceNativeScanRecovery.Mode.LOCAL, recovery.mode)
        recovery.receive("scanner-process-disconnected")
        assertEquals(DeviceNativeScanRecovery.Mode.PAUSED, recovery.mode)
        assertEquals(2, recovery.failures)
    }

    @Test fun memoryFallbackPreservesLocalChecksButStopsAfterProcessFailure() {
        val recovery = DeviceNativeScanRecovery(officialAvailable = true)
        recovery.receive("clamav-official-device-memory")
        assertEquals(DeviceNativeScanRecovery.Mode.LOCAL, recovery.mode)
        assertEquals(0, recovery.failures)
        recovery.receive("scanner-worker-crash")
        assertEquals(DeviceNativeScanRecovery.Mode.PAUSED, recovery.mode)
        assertEquals(1, recovery.failures)
    }

    @Test fun aStoppedScanDoesNotRetryTheFileAfterYaraInterrupted() {
        val recovery = DeviceNativeScanRecovery(officialAvailable = true)
        var attempts = 0
        recovery.scan(stopped = { true }, observe = {}) { _, _ ->
            attempts++
            NativeScanProtocol.unavailable("scanner-native-crash").copy(interruptedStage = "YARA_X")
        }
        assertEquals(1, attempts)
        assertEquals(DeviceNativeScanRecovery.Mode.FULL, recovery.mode)
    }
}
