package com.kanaf.alrasby.engine

import org.junit.Assert.*
import org.junit.Test

class PrivateDnsCompatibilityTest {
    @Test fun automaticModeWorksWithEncryptedDohForwardingWhileStrictModeFailsClosed() {
        assertTrue(PrivateDnsCompatibility.interpret("off", null, null).allowsLocalVpn)
        assertFalse(PrivateDnsCompatibility.interpret(
            "off", null, null, encryptedDnsActive = true).allowsLocalVpn)
        assertTrue(PrivateDnsCompatibility.interpret("opportunistic", null, null).allowsLocalVpn)
        assertTrue(PrivateDnsCompatibility.interpret(
            "opportunistic", null, null, encryptedDnsActive = true).allowsLocalVpn)
        assertFalse(PrivateDnsCompatibility.interpret(
            "hostname", null, "family.adguard-dns.com").allowsLocalVpn)
        assertFalse(PrivateDnsCompatibility.interpret("future", null, null).allowsLocalVpn)
        assertTrue(PrivateDnsCompatibility.interpret(null, null, null).allowsLocalVpn)
    }

    @Test fun providerModeReflectsConfiguredHostWithoutFalsifyingStatus() {
        val result = PrivateDnsCompatibility.interpret(
            "hostname", "off", "family.adguard-dns.com")
        assertEquals(PrivateDnsCompatibility.Mode.PROVIDER, result.mode)
        assertEquals("family.adguard-dns.com", result.provider)
        assertEquals(PrivateDnsCompatibility.Mode.AUTOMATIC,
            PrivateDnsCompatibility.interpret(null, "opportunistic", null).mode)
    }

    @Test fun acceptsHostnamesButNotUrlsOrRawIp() {
        assertTrue(PrivateDnsCompatibility.validHostname("family.adguard-dns.com"))
        assertTrue(PrivateDnsCompatibility.validHostname("dns.adguard-dns.com"))
        assertFalse(PrivateDnsCompatibility.validHostname("https://dns.adguard.com"))
        assertFalse(PrivateDnsCompatibility.validHostname("1.1.1.1"))
        assertFalse(PrivateDnsCompatibility.validHostname("x"))
        assertFalse(PrivateDnsCompatibility.validHostname("bad_name.example"))
    }
}
