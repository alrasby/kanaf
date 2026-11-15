package com.kanaf.alrasby.engine

import org.junit.Assert.*
import org.junit.Test

class PrivateDnsToggleTest {
    @Test fun noPrivilegedHandoffIsRequiredForAutomaticAndOffModes() {
        assertEquals(PrivateDnsToggle.Decision.READY,
            PrivateDnsToggle.decision(PrivateDnsCompatibility.interpret(
                "opportunistic", null, null, encryptedDnsActive = true)))
        assertEquals(PrivateDnsToggle.Decision.READY,
            PrivateDnsToggle.decision(PrivateDnsCompatibility.interpret(
                "off", null, null)))
        assertEquals(PrivateDnsToggle.Decision.MANUAL_REQUIRED,
            PrivateDnsToggle.decision(PrivateDnsCompatibility.interpret(
                "hostname", null, "family.adguard-dns.com")))
        assertEquals(PrivateDnsToggle.Decision.MANUAL_REQUIRED,
            PrivateDnsToggle.decision(PrivateDnsCompatibility.interpret(
                "invalid", null, null)))
    }
}
