package com.kanaf.alrasby.engine

import org.junit.Assert.*
import org.junit.Test

class AutomaticDeviceScanMetadataTest {
    @Test fun updateAvailabilityMatchesTheBuildsPublisherProvisioning() {
        val status = ThreatRuleUpdater().availability()
        // The downloadable test APK now has the publisher's PUBLIC key
        // and HTTPS feed. A bare CI build still has neither.
        val configured = com.kanaf.alrasby.BuildConfig.KANAF_SIGNATURE_PUBLIC_KEY_BASE64.isNotBlank() &&
            com.kanaf.alrasby.BuildConfig.KANAF_SIGNATURE_FEED_URL.isNotBlank()
        assertEquals(configured, status.configured)
        assertTrue(status.reason.isNotBlank())
    }
}
