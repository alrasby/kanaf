package com.kanaf.alrasby.engine

import java.security.MessageDigest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class NativeScannerBridgeTest {
    @Test fun officialEicarVectorHasExpectedLengthAndMd5() {
        val bytes = NativeScannerBridge.eicarReferenceForTests()
        assertEquals(68, bytes.size)
        val md5 = MessageDigest.getInstance("MD5").digest(bytes)
            .joinToString("") { "%02x".format(it.toInt() and 0xff) }
        assertEquals("44d88612fea8a8f36de82e1278abb02f", md5)
    }

    @Test fun malformedNativeOutcomeFailsClosed() {
        val outcome = NativeScannerBridge.decodeForTests("BROKEN", "fake-sha")
        assertTrue(outcome is AntivirusEngine.Verdict.Incomplete)
    }

    @Test fun explicitInfectionAndNoMatchAreDistinct() {
        val infected = NativeScannerBridge.decodeForTests("DETECTED:Kanaf.EICAR.Test", "sha")
        val noMatch = NativeScannerBridge.decodeForTests("NO_MATCH", "sha")
        assertTrue(infected is AntivirusEngine.Verdict.Detected)
        assertTrue(noMatch is AntivirusEngine.Verdict.NoKnownMatch)
    }
}
