package com.kanaf.alrasby

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.kanaf.alrasby.engine.ApkStructureInspector
import com.kanaf.alrasby.engine.DexHeaderInspector
import com.kanaf.alrasby.engine.ExperimentalApkStructureModel
import com.kanaf.alrasby.engine.ThreatFeatureVector
import com.kanaf.alrasby.engine.ThreatModel
import com.kanaf.alrasby.engine.ZipInspector
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.FileInputStream
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Reads the actual APK installed by Android; no prefilled feature vectors or
 * network downloads. The optional structural model is NOT malware detection.
 */
@RunWith(AndroidJUnit4::class)
class RealApkPipelineAndroidTest {
    @Test fun installedApkPassesAllThreeParsersAndOnDevicePilot() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val path = context.applicationInfo.sourceDir
        val apk = FileInputStream(path).use { ApkStructureInspector().inspect(it) }
        val dex = FileInputStream(path).use { DexHeaderInspector().inspect(it) }
        val zip = FileInputStream(path).use { ZipInspector().inspect(it) }

        assertTrue("Installed APK structure was incomplete: $apk",
            apk is ApkStructureInspector.Result.Complete)
        assertTrue("Installed APK DEX was incomplete: $dex",
            dex is DexHeaderInspector.Result.Complete)
        assertTrue("Installed APK ZIP was incomplete: $zip",
            zip is ZipInspector.Result.Complete)

        val apkSummary = (apk as ApkStructureInspector.Result.Complete).summary
        val dexSummary = (dex as DexHeaderInspector.Result.Complete).summary
        val zipSummary = (zip as ZipInspector.Result.Complete).summary
        assertTrue(apkSummary.hasManifest)
        assertTrue(apkSummary.dexFiles > 0)
        assertEquals(apkSummary.dexFiles, dexSummary.dexFiles)
        assertEquals("Installed APK has invalid DEX headers", 0, dexSummary.invalidHeaders)
        assertEquals(apkSummary.entries, zipSummary.entries)
        assertEquals(apkSummary.expandedBytes, zipSummary.bytesExpanded)

        val input = ThreatFeatureVector.from(apk, dex, zip)
        val result = ExperimentalApkStructureModel.classify(input)
        assertTrue("Actual on-device APK observations must be processed: $result",
            result is ThreatModel.Prediction.Scored)
        val value = (result as ThreatModel.Prediction.Scored).riskProbability
        assertTrue(value.isFinite() && value in 0f..1f)
        assertEquals(ExperimentalApkStructureModel.modelVersion, result.modelVersion)
    }

    private fun makeApk(vararg entries: Pair<String, ByteArray>): ByteArray =
        ByteArrayOutputStream().also { output ->
            ZipOutputStream(output).use { zip ->
                for ((name, bytes) in entries) {
                    zip.putNextEntry(ZipEntry(name))
                    zip.write(bytes)
                    zip.closeEntry()
                }
            }
        }.toByteArray()

    @Test fun corruptDexInsideReadableApkGeneratesStructuralRiskEvidence() {
        val file = makeApk(
            "AndroidManifest.xml" to byteArrayOf(0x01),
            "classes.dex" to byteArrayOf(0x00, 0x01, 0x02),
            "assets/payload.bin" to byteArrayOf(0x42)
        )
        val apk = ApkStructureInspector().inspect(ByteArrayInputStream(file))
        val dex = DexHeaderInspector().inspect(ByteArrayInputStream(file))
        val zip = ZipInspector().inspect(ByteArrayInputStream(file))
        assertTrue("APK parser unexpectedly incomplete: $apk",
            apk is ApkStructureInspector.Result.Complete)
        assertTrue("DEX parser unexpectedly incomplete: $dex",
            dex is DexHeaderInspector.Result.Complete)
        assertTrue("ZIP parser unexpectedly incomplete: $zip",
            zip is ZipInspector.Result.Complete)
        assertTrue((dex as DexHeaderInspector.Result.Complete).summary.invalidHeaders > 0)
        val score = ExperimentalApkStructureModel.classify(
            ThreatFeatureVector.from(apk, dex, zip))
        assertTrue("Corrupt DEX must produce structural evidence: $score",
            score is ThreatModel.Prediction.Scored)
        assertTrue((score as ThreatModel.Prediction.Scored).riskProbability > .8f)

        val omitted = ExperimentalApkStructureModel.classify(
            ThreatFeatureVector.from(apk, null, zip))
        assertTrue("Missing DEX analysis must never be treated as clean",
            omitted is ThreatModel.Prediction.Unavailable)
    }

    @Test fun traversalZipIsEitherRejectedOrReportedUnsafeAcrossAndroidVersions() {
        val file = makeApk(
            "AndroidManifest.xml" to byteArrayOf(0x01),
            "classes.dex" to byteArrayOf(0x00, 0x01, 0x02),
            "../traversal.txt" to byteArrayOf(0x42)
        )
        val apk = ApkStructureInspector().inspect(ByteArrayInputStream(file))
        val dex = DexHeaderInspector().inspect(ByteArrayInputStream(file))
        val zip = ZipInspector().inspect(ByteArrayInputStream(file))
        // Android releases differ: newer ZIP readers can reject traversal
        // names while older versions allow reading and report unsafe paths.
        if (apk is ApkStructureInspector.Result.Complete) {
            assertTrue("Accepted traversal must be flagged",
                apk.summary.unsafePaths > 0)
        } else assertTrue(apk is ApkStructureInspector.Result.Incomplete)
        if (zip is ZipInspector.Result.Complete) {
            assertTrue("Accepted traversal must be flagged",
                zip.summary.unsafeNames > 0)
        } else assertTrue(zip is ZipInspector.Result.Incomplete)
        val classification = ExperimentalApkStructureModel.classify(
            ThreatFeatureVector.from(apk, dex, zip))
        if (apk is ApkStructureInspector.Result.Complete &&
            dex is DexHeaderInspector.Result.Complete &&
            zip is ZipInspector.Result.Complete) {
            assertTrue("Fully observed unsafe ZIP must generate structural evidence",
                classification is ThreatModel.Prediction.Scored)
            assertTrue((classification as ThreatModel.Prediction.Scored).riskProbability > .8f)
        } else {
            assertTrue("Rejected/incomplete ZIP must not be scored as safe",
                classification is ThreatModel.Prediction.Unavailable)
        }
    }

}
