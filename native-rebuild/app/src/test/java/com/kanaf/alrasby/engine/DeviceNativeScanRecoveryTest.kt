package com.kanaf.alrasby.engine

import org.junit.Assert.assertEquals
import org.junit.Test

class DeviceNativeScanRecoveryTest {
    @Test fun processFailuresAllowOneFallbackBeforePausing() {
        val recovery = DeviceNativeScanRecovery(officialAvailable = true)
        recovery.record("INCOMPLETE:clamav-scan-time-limit")
        assertEquals(DeviceNativeScanRecovery.Mode.FULL, recovery.mode)
        assertEquals(0, recovery.failures)

        recovery.record("scanner-native-crash")
        assertEquals(DeviceNativeScanRecovery.Mode.LOCAL, recovery.mode)
        recovery.record("scanner-process-disconnected")
        assertEquals(DeviceNativeScanRecovery.Mode.PAUSED, recovery.mode)
        assertEquals(2, recovery.failures)
    }

    @Test fun memoryFallbackPreservesLocalChecksButStopsAfterProcessFailure() {
        val recovery = DeviceNativeScanRecovery(officialAvailable = true)
        recovery.record("clamav-official-device-memory")
        assertEquals(DeviceNativeScanRecovery.Mode.LOCAL, recovery.mode)
        assertEquals(0, recovery.failures)
        recovery.record("scanner-worker-crash")
        assertEquals(DeviceNativeScanRecovery.Mode.PAUSED, recovery.mode)
        assertEquals(1, recovery.failures)
    }
}
