package com.kanaf.alrasby.engine

import org.junit.Assert.*
import org.junit.Test
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream

class ZipInspectorTest {
    private fun zip(vararg entries: Pair<String, ByteArray>): ByteArray {
        val output = ByteArrayOutputStream()
        ZipOutputStream(output).use { archive ->
            for ((name, data) in entries) {
                archive.putNextEntry(ZipEntry(name))
                archive.write(data)
                archive.closeEntry()
            }
        }
        return output.toByteArray()
    }
    @Test fun scansSimpleArchive() {
        val result = ZipInspector().inspect(ByteArrayInputStream(zip("a.txt" to "abc".toByteArray())))
        assertEquals(1, (result as ZipInspector.Result.Complete).summary.entries)
        assertEquals(3L, (result as ZipInspector.Result.Complete).summary.bytesExpanded)
    }
    @Test fun limitsActualInflatedBytes() {
        val result = ZipInspector(maxEntryBytes = 8).inspect(
            ByteArrayInputStream(zip("a.txt" to ByteArray(1000)))
        )
        assertEquals("entry-size-limit", (result as ZipInspector.Result.Incomplete).reason)
    }
    @Test fun detectsUnsafeNames() {
        val result = ZipInspector().inspect(ByteArrayInputStream(zip("../escape" to byteArrayOf(1))))
        assertEquals(1, (result as ZipInspector.Result.Complete).summary.unsafeNames)
    }
    @Test fun cancellationIsIncomplete() {
        val result = ZipInspector().inspect(ByteArrayInputStream(zip("a" to byteArrayOf(1)))) { true }
        assertEquals("cancelled", (result as ZipInspector.Result.Incomplete).reason)
    }
    @Test fun stopsOnDeterministicTimeBudget() {
        var ticks = 0L
        val inspector = ZipInspector(maxDurationNanos = 3L, nanoTime = { ticks++ })
        val result = inspector.inspect(ByteArrayInputStream(zip("file" to ByteArray(256))))
        assertEquals("time-limit", (result as ZipInspector.Result.Incomplete).reason)
    }
    @Test fun rejectsInvalidTimeBudget() {
        try {
            ZipInspector(maxDurationNanos = 0L)
            fail("Should reject an invalid deadline")
        } catch (_: IllegalArgumentException) { }
    }
    @Test fun flagsWindowsAbsolutePaths() {
        val result = ZipInspector().inspect(ByteArrayInputStream(zip("C:\\temp\\file.txt" to byteArrayOf(1))))
        assertEquals(1, (result as ZipInspector.Result.Complete).summary.unsafeNames)
    }
    @Test fun elapsedAfterLastEntryIsNotReportedComplete() {
        var ticks = 0L
        val result = ZipInspector(maxDurationNanos = 6L, nanoTime = { ticks++ })
            .inspect(ByteArrayInputStream(zip("file" to byteArrayOf(1))))
        assertEquals("time-limit", (result as ZipInspector.Result.Incomplete).reason)
    }
}
