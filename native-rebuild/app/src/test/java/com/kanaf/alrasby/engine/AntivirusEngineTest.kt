package com.kanaf.alrasby.engine

import org.junit.Assert.*
import org.junit.Test
import java.io.ByteArrayInputStream

class AntivirusEngineTest {
    private val digest = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    @Test fun knownSignatureDetected() {
        val engine = HashSignatureEngine(mapOf(digest to "test-only"))
        val verdict = engine.scan({ ByteArrayInputStream("abc".toByteArray()) })
        assertEquals("test-only", (verdict as AntivirusEngine.Verdict.Detected).threatName)
    }
    @Test fun unknownSignatureNotClaimedSafe() {
        val verdict = HashSignatureEngine(emptyMap()).scan({ ByteArrayInputStream("abc".toByteArray()) })
        assertEquals(AntivirusEngine.Verdict.NoKnownMatch, verdict)
    }
    @Test fun missingDatabaseIsIncomplete() {
        val verdict = HashSignatureEngine(null).scan({ ByteArrayInputStream("abc".toByteArray()) })
        assertEquals("signature-database-unavailable", (verdict as AntivirusEngine.Verdict.Incomplete).reason)
    }
    @Test fun missingFileIsIncomplete() {
        val verdict = HashSignatureEngine(emptyMap()).scan({ null })
        assertEquals("file-unavailable", (verdict as AntivirusEngine.Verdict.Incomplete).reason)
    }
    @Test fun cancelledScanIsIncomplete() {
        val verdict = HashSignatureEngine(emptyMap()).scan({ ByteArrayInputStream(byteArrayOf(1)) }) { true }
        assertEquals("cancelled", (verdict as AntivirusEngine.Verdict.Incomplete).reason)
    }
    @Test fun readFailureIsIncomplete() {
        val verdict = HashSignatureEngine(emptyMap()).scan({ throw java.io.IOException("test") })
        assertEquals("read-failed", (verdict as AntivirusEngine.Verdict.Incomplete).reason)
    }
}
