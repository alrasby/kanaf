package com.kanaf.alrasby.engine

import org.junit.Assert.*
import org.junit.Test
import java.io.ByteArrayInputStream

class StreamScannerTest {
    @Test fun hashesKnownContent() {
        val result = StreamScanner().scan(ByteArrayInputStream("abc".toByteArray()))
        assertTrue(result is StreamScanner.Result.Completed)
        result as StreamScanner.Result.Completed
        assertEquals("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", result.sha256)
        assertEquals(3L, result.bytesRead)
        assertNull(result.signature)
    }
    @Test fun detectsKnownHash() {
        val sha = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        val result = StreamScanner(signatures = mapOf(sha to "test-signature")).scan(ByteArrayInputStream("abc".toByteArray()))
        assertEquals("test-signature", (result as StreamScanner.Result.Completed).signature)
    }
    @Test fun respectsSizeLimit() {
        val result = StreamScanner(maxBytes = 2).scan(ByteArrayInputStream("abc".toByteArray()))
        assertEquals("size-limit", (result as StreamScanner.Result.Skipped).reason)
    }
    @Test fun respectsCancellation() {
        val result = StreamScanner().scan(ByteArrayInputStream("abc".toByteArray())) { true }
        assertEquals("cancelled", (result as StreamScanner.Result.Skipped).reason)
    }
}
