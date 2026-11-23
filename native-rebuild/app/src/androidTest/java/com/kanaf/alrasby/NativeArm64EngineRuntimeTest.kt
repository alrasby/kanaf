package com.kanaf.alrasby

import android.net.Uri
import android.os.Build
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.kanaf.alrasby.engine.AntivirusEngine
import com.kanaf.alrasby.engine.NativeScannerBridge
import com.kanaf.alrasby.engine.OfficialClamDatabase
import com.kanaf.alrasby.engine.ThreatFamily
import java.io.File
import java.security.MessageDigest
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Strict native ARM64 runtime evidence, NOT x86_64 IPC-only smoke tests.
 * Runs only from the experimental ARM64-enabled emulator workflow.
 */
@RunWith(AndroidJUnit4::class)
class NativeArm64EngineRuntimeTest {
    private val appContext get() = InstrumentationRegistry.getInstrumentation().targetContext

    private fun requireArm64() {
        assertTrue("Android ABI does not include ARM64: " +
            Build.SUPPORTED_ABIS.joinToString(), Build.SUPPORTED_ABIS.contains("arm64-v8a"))
    }
    private fun sha256(bytes: ByteArray): String =
        MessageDigest.getInstance("SHA-256").digest(bytes)
            .joinToString("") { "%02x".format(it.toInt() and 0xff) }

    @Test fun bothActualArm64EnginesPassEicarSelfTestThroughWorkerIpc() {
        requireArm64()
        val report = NativeScannerBridge.selfTest(appContext)
        println("Kanaf native ARM64 self-test report: " + report)
        assertEquals(2, report.gates.size)
        assertTrue("ClamAV failed readiness: " + report,
            report.gates.single { it.engineId == "clamav" }.ready)
        assertTrue("YARA-X failed readiness: " + report,
            report.gates.single { it.engineId == "yara-x" }.ready)
        assertTrue("ClamAV must DETECT EICAR: " + report,
            report.clamav is AntivirusEngine.Verdict.Detected)
        assertTrue("YARA-X must DETECT EICAR: " + report,
            report.yaraX is AntivirusEngine.Verdict.Detected)
        val expected = sha256(NativeScannerBridge.eicarReferenceForTests())
        val clam = report.clamav as AntivirusEngine.Verdict.Detected
        val yara = report.yaraX as AntivirusEngine.Verdict.Detected
        if (OfficialClamDatabase.bundled) {
            assertTrue(report.gates.single { it.engineId == "clamav" }.rulesVersion?.startsWith("official-") == true)
            assertEquals(ThreatFamily.Kind.TEST_SAMPLE, ThreatFamily.classify(clam.threatName))
        } else {
            assertEquals("Kanaf.EICAR.Test", clam.threatName.removeSuffix(".UNOFFICIAL"))
        }
        assertEquals("Kanaf_EICAR_Test", yara.threatName)
        assertEquals(expected, clam.sha256)
        assertEquals(expected, yara.sha256)
    }

    @Test fun nativeEnginesAcceptSelectedFileLargerThanPreviousLimit() {
        requireArm64()
        val file = File.createTempFile("large-benign-", ".bin", appContext.cacheDir)
        try {
            java.io.RandomAccessFile(file, "rw").use { it.setLength(20L * 1024 * 1024) }
            val result = NativeScannerBridge.scan(appContext, Uri.fromFile(file))
            assertTrue("ClamAV must complete the 20 MiB fixture: $result",
                result.clamav is AntivirusEngine.Verdict.NoKnownMatch)
            assertTrue("YARA-X must complete the 20 MiB fixture: $result",
                result.yaraX is AntivirusEngine.Verdict.NoKnownMatch)
        } finally {
            file.delete()
        }
    }

    @Test fun oversizedSelectedFileMustFailClosedInBothNativeEngines() {
        requireArm64()
        val file = File.createTempFile("oversize-probe-", ".bin", appContext.cacheDir)
        try {
            java.io.RandomAccessFile(file, "rw").use {
                it.setLength(NativeScannerBridge.inputLimit + 1)
            }
            val result = NativeScannerBridge.scan(appContext, Uri.fromFile(file))
            assertTrue("ClamAV must refuse an oversize source: $result",
                result.clamav is AntivirusEngine.Verdict.Incomplete)
            assertTrue("YARA-X must refuse an oversize source: $result",
                result.yaraX is AntivirusEngine.Verdict.Incomplete)
            assertEquals("copy-size-limit",
                (result.clamav as AntivirusEngine.Verdict.Incomplete).reason)
            assertEquals("copy-size-limit",
                (result.yaraX as AntivirusEngine.Verdict.Incomplete).reason)
        } finally {
            file.delete()
        }
    }

    @Test fun officialClamAvCompletesSeventyMiBAndYaraReportsItsOwnLimit() {
        requireArm64()
        assumeTrue(OfficialClamDatabase.bundled)
        val file = File.createTempFile("large-official-control-", ".bin", appContext.cacheDir)
        try {
            java.io.RandomAccessFile(file, "rw").use { it.setLength(70L * 1024 * 1024) }
            val result = NativeScannerBridge.scan(appContext, Uri.fromFile(file))
            assertTrue("The full database must actually scan the control: $result",
                result.gates.single { it.engineId == "clamav" }.rulesVersion?.startsWith("official-") == true)
            assertTrue("ClamAV did not complete the 70 MiB control: $result",
                result.clamav is AntivirusEngine.Verdict.NoKnownMatch)
            assertEquals(AntivirusEngine.Verdict.Incomplete("yara-input-size-limit"), result.yaraX)
        } finally {
            file.delete()
        }
    }

    @Test fun officialClamAvScansCompressedEntriesInApkShapedArchive() {
        requireArm64()
        assumeTrue(OfficialClamDatabase.bundled)
        val file = File.createTempFile("apk-archive-control-", ".apk", appContext.cacheDir)
        try {
            ZipOutputStream(file.outputStream()).use { archive ->
                archive.putNextEntry(ZipEntry("AndroidManifest.xml"))
                archive.write("<manifest package=\"com.kanaf.archive.control\"/>".toByteArray())
                archive.closeEntry()
                archive.putNextEntry(ZipEntry("assets/sample.txt"))
                archive.write(NativeScannerBridge.eicarReferenceForTests())
                archive.closeEntry()
            }
            val result = NativeScannerBridge.scan(appContext, Uri.fromFile(file))
            assertTrue(result.gates.single { it.engineId == "clamav" }.rulesVersion?.startsWith("official-") == true)
            assertTrue("Official ClamAV did not detect the compressed EICAR control: $result",
                result.clamav is AntivirusEngine.Verdict.Detected)
            assertEquals(ThreatFamily.Kind.TEST_SAMPLE,
                ThreatFamily.classify((result.clamav as AntivirusEngine.Verdict.Detected).threatName))
        } finally {
            file.delete()
        }
    }

    @Test fun actualArm64EnginesScanBothBenignAndEicarFiles() {
        requireArm64()
        fun scanBytes(bytes: ByteArray): NativeScannerBridge.Report {
            // Do not use "kanaf-" prefix; :scanner clears its own stale cache files.
            val file = File.createTempFile("runtime-sample-", ".bin", appContext.cacheDir)
            return try {
                file.writeBytes(bytes)
                NativeScannerBridge.scan(appContext, Uri.fromFile(file))
            } finally {
                file.delete()
            }
        }
        val benign = "kanaf-runtime-benign".toByteArray(Charsets.US_ASCII)
        val result = scanBytes(benign)
        println("Kanaf ARM64 benign file report: " + result)
        assertTrue("ClamAV benign file must return NoKnownMatch: " + result,
            result.clamav is AntivirusEngine.Verdict.NoKnownMatch)
        assertTrue("YARA-X benign file must return NoKnownMatch: " + result,
            result.yaraX is AntivirusEngine.Verdict.NoKnownMatch)
        assertEquals(sha256(benign),
            (result.clamav as AntivirusEngine.Verdict.NoKnownMatch).sha256)
        assertEquals(sha256(benign),
            (result.yaraX as AntivirusEngine.Verdict.NoKnownMatch).sha256)

        val eicar = NativeScannerBridge.eicarReferenceForTests()
        val positive = scanBytes(eicar)
        println("Kanaf ARM64 EICAR file report: " + positive)
        assertTrue("ClamAV must DETECT EICAR file: " + positive,
            positive.clamav is AntivirusEngine.Verdict.Detected)
        assertTrue("YARA-X must DETECT EICAR file: " + positive,
            positive.yaraX is AntivirusEngine.Verdict.Detected)
        assertEquals(sha256(eicar),
            (positive.clamav as AntivirusEngine.Verdict.Detected).sha256)
        assertEquals(sha256(eicar),
            (positive.yaraX as AntivirusEngine.Verdict.Detected).sha256)
    }
    @Test fun realYaraContentRuleRunsOnHarmlessControlAndRejectsNearMiss() {
        requireArm64()
        val parts = listOf("Modules are loaded", "--scrypt", "processor ", "cpu model ", "Host: www.challpok.cn")
        val positive = byteArrayOf(0x7f, 0x45, 0x4c, 0x46) + parts.joinToString("\u0000").toByteArray()
        val nearMiss = byteArrayOf(0x7f, 0x45, 0x4c, 0x46) + parts.take(4).joinToString("\u0000").toByteArray()
        val file = File.createTempFile("real-rule-control-", ".bin", appContext.cacheDir)
        try {
            file.writeBytes(positive)
            val detected = NativeScannerBridge.scan(appContext, Uri.fromFile(file))
            assertTrue("Real ESET content rule did not run: $detected", detected.yaraX is AntivirusEngine.Verdict.Detected)
            assertEquals("moose_2", (detected.yaraX as AntivirusEngine.Verdict.Detected).threatName)
            file.writeBytes(nearMiss)
            val negative = NativeScannerBridge.scan(appContext, Uri.fromFile(file))
            assertTrue("Near-miss must not reuse an old verdict: $negative", negative.yaraX is AntivirusEngine.Verdict.NoKnownMatch)
        } finally { file.delete() }
        // Generated control bytes prove rule execution, not malware recall.
    }

    @Test fun reversingLabsContentRuleUsesTheActualArm64EngineOnSafeControls() {
        requireArm64()
        val fixtures = InstrumentationRegistry.getInstrumentation().context.assets
        fun bytes(name: String): ByteArray {
            val hex = fixtures.open(name).bufferedReader().use { it.readText().trim() }
            return ByteArray(hex.length / 2) { hex.substring(it * 2, it * 2 + 2).toInt(16).toByte() }
        }
        val file = File.createTempFile("rl-safe-control-", ".bin", appContext.cacheDir)
        try {
            file.writeBytes(bytes("rl-positive-control.hex"))
            val positive = NativeScannerBridge.scan(appContext, Uri.fromFile(file))
            assertTrue("ReversingLabs rule did not execute: $positive", positive.yaraX is AntivirusEngine.Verdict.Detected)
            assertEquals("Linux_Trojan_AcidRain", (positive.yaraX as AntivirusEngine.Verdict.Detected).threatName)
            file.writeBytes(bytes("rl-near-miss-control.hex"))
            val negative = NativeScannerBridge.scan(appContext, Uri.fromFile(file))
            assertTrue("Partial pattern must not match: $negative", negative.yaraX is AntivirusEngine.Verdict.NoKnownMatch)
        } finally { file.delete() }
        // These are incomplete, non-executable ELF-shaped controls, not malware.
    }

}
