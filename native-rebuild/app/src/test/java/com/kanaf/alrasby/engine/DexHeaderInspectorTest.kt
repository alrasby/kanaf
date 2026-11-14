package com.kanaf.alrasby.engine

import org.junit.Assert.*
import org.junit.Test
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream

class DexHeaderInspectorTest {
    private fun dex(): ByteArray {
        val data = ByteArray(112)
        "dex\n035\u0000".toByteArray(Charsets.US_ASCII).copyInto(data)
        ByteBuffer.wrap(data).order(ByteOrder.LITTLE_ENDIAN).apply {
            putInt(32, 112)
            putInt(36, 112)
            putInt(40, 0x12345678)
        }
        return data
    }
    private fun apk(name: String, payload: ByteArray): ByteArray {
        val out = ByteArrayOutputStream()
        ZipOutputStream(out).use { zip ->
            zip.putNextEntry(ZipEntry(name))
            zip.write(payload)
            zip.closeEntry()
        }
        return out.toByteArray()
    }
    @Test fun validHeaderIsRecognized() {
        assertTrue(DexHeaderInspector.validDexHeader(dex(), 112, 112))
    }
    @Test fun mismatchedSizeIsRejected() {
        assertFalse(DexHeaderInspector.validDexHeader(dex(), 112, 113))
    }
    @Test fun malformedDexIsCounted() {
        val result = DexHeaderInspector().inspect(ByteArrayInputStream(apk("classes.dex", byteArrayOf(1, 2))))
        assertEquals(1, (result as DexHeaderInspector.Result.Complete).summary.invalidHeaders)
    }
    @Test fun validDexIsCounted() {
        val result = DexHeaderInspector().inspect(ByteArrayInputStream(apk("classes.dex", dex())))
        assertEquals(0, (result as DexHeaderInspector.Result.Complete).summary.invalidHeaders)
    }
    @Test fun noDexIsIncomplete() {
        val result = DexHeaderInspector().inspect(ByteArrayInputStream(apk("readme.txt", byteArrayOf(1))))
        assertEquals("no-dex-files", (result as DexHeaderInspector.Result.Incomplete).reason)
    }
    @Test fun byteLimitIsEnforced() {
        val result = DexHeaderInspector(maxTotalBytes = 10).inspect(ByteArrayInputStream(apk("classes.dex", dex())))
        assertEquals("expanded-size-limit", (result as DexHeaderInspector.Result.Incomplete).reason)
    }
    @Test fun cancellationIsEnforced() {
        val result = DexHeaderInspector().inspect(ByteArrayInputStream(apk("classes.dex", dex()))) { true }
        assertEquals("cancelled", (result as DexHeaderInspector.Result.Incomplete).reason)
    }
}
