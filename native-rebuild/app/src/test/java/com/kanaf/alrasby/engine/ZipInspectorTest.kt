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
}
