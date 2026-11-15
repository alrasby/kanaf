package com.kanaf.alrasby.engine

import org.junit.Assert.*
import org.junit.Test

class AutomaticDeviceScanMetadataTest {
    @Test fun signaturesAreUnavailableWithoutPublisherProvisioning() {
        val status = ThreatRuleUpdater().availability()
        // CI intentionally has no production signing key or official feed.
        assertFalse(status.configured)
        assertTrue(status.reason.isNotBlank())
    }
}
