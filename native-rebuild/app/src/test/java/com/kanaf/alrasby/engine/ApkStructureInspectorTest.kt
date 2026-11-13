package com.kanaf.alrasby.engine

import org.junit.Assert.*
import org.junit.Test
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream

class ApkStructureInspectorTest {
    private fun archive(vararg names: String): ByteArray {
        val bytes = ByteArrayOutputStream()
        ZipOutputStream(bytes).use { zip ->
            names.forEach { name ->
                zip.putNextEntry(ZipEntry(name))
                zip.write(byteArrayOf(1, 2, 3))
                zip.closeEntry()
            }
        }
        return bytes.toByteArray()
    }

    @Test fun validStructureCountsDexAndNativeLibraries() {
        val data = archive("AndroidManifest.xml", "classes.dex", "classes2.dex", "lib/arm64-v8a/liba.so", "resources.arsc")
        val result = ApkStructureInspector().inspect(ByteArrayInputStream(data))
        assertTrue(result is ApkStructureInspector.Result.Complete)
        val summary = (result as ApkStructureInspector.Result.Complete).summary
        assertEquals(2, summary.dexFiles)
        assertEquals(1, summary.nativeLibraries)
        assertEquals(0, summary.unsafePaths)
    }

    @Test fun missingDexIsIncomplete() {
        val result = ApkStructureInspector().inspect(ByteArrayInputStream(archive("AndroidManifest.xml")))
        assertEquals("missing-required-apk-components", (result as ApkStructureInspector.Result.Incomplete).reason)
    }

    @Test fun traversalIsReportedWithoutExtraction() {
        val result = ApkStructureInspector().inspect(ByteArrayInputStream(archive("AndroidManifest.xml", "classes.dex", "../escape")))
        assertEquals(1, (result as ApkStructureInspector.Result.Complete).summary.unsafePaths)
    }

    @Test fun entryLimitFailsClosed() {
        val result = ApkStructureInspector(maxEntries = 1).inspect(ByteArrayInputStream(archive("AndroidManifest.xml", "classes.dex")))
        assertEquals("entry-limit", (result as ApkStructureInspector.Result.Incomplete).reason)
    }

    @Test fun expandedLimitFailsClosed() {
        val result = ApkStructureInspector(maxExpandedBytes = 2).inspect(ByteArrayInputStream(archive("AndroidManifest.xml", "classes.dex")))
        assertEquals("expanded-size-limit", (result as ApkStructureInspector.Result.Incomplete).reason)
    }

    @Test fun cancellationFailsClosed() {
        val result = ApkStructureInspector().inspect(ByteArrayInputStream(archive("AndroidManifest.xml", "classes.dex"))) { true }
        assertEquals("cancelled", (result as ApkStructureInspector.Result.Incomplete).reason)
    }

    @Test fun invalidArchiveFailsClosed() {
        val result = ApkStructureInspector().inspect(ByteArrayInputStream(byteArrayOf(1, 2, 3)))
        assertTrue(result is ApkStructureInspector.Result.Incomplete)
    }
}
