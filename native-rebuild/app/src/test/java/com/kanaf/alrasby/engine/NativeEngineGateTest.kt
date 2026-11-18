package com.kanaf.alrasby.engine

import org.junit.Assert.*
import org.junit.Test

class NativeEngineGateTest {
    @Test fun missingLibraryFailsClosed() {
        val gate = NativeEngineGate("clamav", false, true, true, "1.0", "daily-1")
        assertFalse(gate.ready)
        assertEquals("native-library-unavailable", gate.unavailableReason())
        assertTrue(GatedNativeEngine(gate).scan({ null }) is AntivirusEngine.Verdict.Incomplete)
    }
    @Test fun unsignedRulesFailClosed() {
        val gate = NativeEngineGate("yara-x", true, false, true, "1.0", "rules-1")
        assertFalse(gate.ready)
        assertEquals("rules-not-verified", gate.unavailableReason())
    }
    @Test fun selfTestIsMandatory() {
        val gate = NativeEngineGate("clamav", true, true, false, "1.0", "daily-1")
        assertFalse(gate.ready)
        assertEquals("self-test-not-passed", gate.unavailableReason())
    }
    @Test fun versionMetadataIsMandatory() {
        val gate = NativeEngineGate("yara-x", true, true, true, "", "rules-1")
        assertFalse(gate.ready)
        assertEquals("version-metadata-unavailable", gate.unavailableReason())
    }
    @Test fun readyDoesNotPretendNativeScannerExists() {
        val gate = NativeEngineGate("clamav", true, true, true, "1.0", "daily-1")
        assertTrue(gate.ready)
        assertEquals("native-scanner-not-integrated",
            (GatedNativeEngine(gate).scan({ null }) as AntivirusEngine.Verdict.Incomplete).reason)
    }
}
