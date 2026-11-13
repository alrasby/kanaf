package com.kanaf.alrasby.engine

import org.junit.Assert.*
import org.junit.Test
import java.io.ByteArrayInputStream

class StreamScannerTest {
    @Test fun rejectsInvalidTimeBudget() {
        try {
            StreamScanner(maxDurationNanos = 0)
            fail("Expected invalid budget to be rejected")
        } catch (_: IllegalArgumentException) {
            // Expected.
        }
    }
    @Test fun timeBudgetFailsClosed() {
        val slow = object : java.io.InputStream() {
            private var remaining = 3
            override fun read(): Int {
                Thread.sleep(2)
                return if (remaining-- > 0) 42 else -1
            }
            override fun read(b: ByteArray, off: Int, len: Int): Int {
                Thread.sleep(2)
                if (remaining-- <= 0) return -1
                b[off] = 42
                return 1
            }
        }
        val result = StreamScanner(maxDurationNanos = 1).scan(slow)
        assertEquals("time-limit", (result as StreamScanner.Result.Skipped).reason)
    }
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
    @Test fun rejectsStalledStream() {
        val stalled = object : java.io.InputStream() {
            override fun read(): Int = 0
            override fun read(b: ByteArray, off: Int, len: Int): Int = 0
        }
        val result = StreamScanner().scan(stalled)
        assertEquals("stalled-stream", (result as StreamScanner.Result.Skipped).reason)
    }
    @Test fun respectsCancellation() {
        val result = StreamScanner().scan(ByteArrayInputStream("abc".toByteArray())) { true }
        assertEquals("cancelled", (result as StreamScanner.Result.Skipped).reason)
    }
}
