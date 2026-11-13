package com.kanaf.alrasby.engine

import org.junit.Assert.*
import org.junit.Test

class ThreatFeatureVectorTest {
    @Test fun noScanIsUnknownNotZero() {
        val vector = ThreatFeatureVector.from(null, null, null)
        assertFalse(vector.hasAnyObservation())
        assertNull(vector.apkUnsafePathCount)
        assertNull(vector.zipEntryCount)
    }

    @Test fun invalidNegativeFeatureIsRejected() {
        try {
            ThreatFeatureVector(apkDexCount = -1, apkNativeLibraryCount = null,
                apkUnsafePathCount = null, dexInvalidHeaderCount = null,
                zipUnsafeNameCount = null, zipEntryCount = null, zipExpandedBytes = null)
            fail("Negative features must be rejected")
        } catch (_: IllegalArgumentException) {
            // Expected
        }
    }

    @Test fun invalidSchemaIsRejected() {
        try {
            ThreatFeatureVector(schemaVersion = 2, apkDexCount = null,
                apkNativeLibraryCount = null, apkUnsafePathCount = null,
                dexInvalidHeaderCount = null, zipUnsafeNameCount = null,
                zipEntryCount = null, zipExpandedBytes = null)
            fail("Unknown schema must be rejected")
        } catch (_: IllegalArgumentException) {
            // Expected
        }
    }
}
