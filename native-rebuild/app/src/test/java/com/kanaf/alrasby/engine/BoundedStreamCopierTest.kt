package com.kanaf.alrasby.engine

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.InputStream
import org.junit.Assert.*
import org.junit.Test

class BoundedStreamCopierTest {
    @Test fun computesStreamingSha256AndCopiesBytes() {
        val data = "abc".toByteArray()
        val output = ByteArrayOutputStream()
        val result = BoundedStreamCopier().copy(ByteArrayInputStream(data), output)
            as BoundedStreamCopier.Result.Complete
        assertEquals("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", result.sha256)
        assertEquals(3L, result.bytesCopied)
        assertArrayEquals(data, output.toByteArray())
    }
    @Test fun oversizeIsNotSilentlyTruncatedToClean() {
        val result = BoundedStreamCopier(maxBytes = 2).copy(
            ByteArrayInputStream("abc".toByteArray()), ByteArrayOutputStream()
        ) as BoundedStreamCopier.Result.Incomplete
        assertEquals("size-limit", result.reason)
    }
    @Test fun cancellationIsIncomplete() {
        val result = BoundedStreamCopier().copy(
            ByteArrayInputStream("abc".toByteArray()), ByteArrayOutputStream()
        ) { true } as BoundedStreamCopier.Result.Incomplete
        assertEquals("cancelled", result.reason)
    }
    @Test fun repeatedZeroReadsAreBounded() {
        val source = object : InputStream() {
            override fun read(): Int = 0
            override fun read(b: ByteArray, off: Int, len: Int): Int = 0
        }
        val result = BoundedStreamCopier().copy(source, ByteArrayOutputStream())
            as BoundedStreamCopier.Result.Incomplete
        assertEquals("stalled-stream", result.reason)
    }
    @Test fun deterministicTimeoutIsIncomplete() {
        var tick = 0L
        val result = BoundedStreamCopier(maxDurationNanos = 2, nanoTime = { tick++ })
            .copy(ByteArrayInputStream("abc".toByteArray()), ByteArrayOutputStream())
            as BoundedStreamCopier.Result.Incomplete
        assertEquals("time-limit", result.reason)
    }
    @Test fun emptyFileCanBeHashed() {
        val result = BoundedStreamCopier().copy(ByteArrayInputStream(byteArrayOf()), ByteArrayOutputStream())
            as BoundedStreamCopier.Result.Complete
        assertEquals(0L, result.bytesCopied)
        assertEquals("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", result.sha256)
    }
    @Test fun rejectsInvalidLimits() {
        try {
            BoundedStreamCopier(maxDurationNanos = 0)
            fail("deadline must be positive")
        } catch (_: IllegalArgumentException) { }
    }
}
