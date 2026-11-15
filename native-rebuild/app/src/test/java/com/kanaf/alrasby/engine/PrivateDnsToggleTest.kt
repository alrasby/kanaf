package com.kanaf.alrasby.engine

import org.junit.Assert.*
import org.junit.Test

class PrivateDnsToggleTest {
    private fun snapshot(mode: PrivateDnsCompatibility.Mode, active: Boolean = false) =
        PrivateDnsCompatibility.Snapshot(mode, encryptedDnsActive = active)

    @Test fun withoutGrantDoesNotOverridePrivateDns() {
        assertEquals(PrivateDnsToggle.Decision.READY, PrivateDnsToggle.decision(
            snapshot(PrivateDnsCompatibility.Mode.OFF), false))
        assertEquals(PrivateDnsToggle.Decision.MANUAL_REQUIRED, PrivateDnsToggle.decision(
            snapshot(PrivateDnsCompatibility.Mode.PROVIDER), false))
        assertEquals(PrivateDnsToggle.Decision.MANUAL_REQUIRED, PrivateDnsToggle.decision(
            snapshot(PrivateDnsCompatibility.Mode.AUTOMATIC), false))
    }

    @Test fun grantEnablesAutoSwitchButUnknownRemainsDenied() {
        assertEquals(PrivateDnsToggle.Decision.AUTO_SWITCH, PrivateDnsToggle.decision(
            snapshot(PrivateDnsCompatibility.Mode.PROVIDER), true))
        assertEquals(PrivateDnsToggle.Decision.AUTO_SWITCH, PrivateDnsToggle.decision(
            snapshot(PrivateDnsCompatibility.Mode.AUTOMATIC), true))
        assertEquals(PrivateDnsToggle.Decision.AUTO_SWITCH, PrivateDnsToggle.decision(
            snapshot(PrivateDnsCompatibility.Mode.OFF, true), true))
        assertEquals(PrivateDnsToggle.Decision.MANUAL_REQUIRED, PrivateDnsToggle.decision(
            snapshot(PrivateDnsCompatibility.Mode.UNKNOWN), true))
    }

    @Test fun grantCommandNamesKanafOnly() {
        assertEquals("adb shell pm grant com.kanaf.alrasby android.permission.WRITE_SECURE_SETTINGS",
            PrivateDnsToggle.GRANT_COMMAND)
    }
}
