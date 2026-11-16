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

    @Test fun malformedApkProducesStructuralWarningNeverMalwareVerdict() {
        val file = ByteArrayOutputStream().also { out ->
            ZipOutputStream(out).use { zip ->
                for ((name, bytes) in listOf(
                    "AndroidManifest.xml" to byteArrayOf(0x01),
                    "classes.dex" to byteArrayOf(0x00, 0x01, 0x02),
                    "../traversal.txt" to byteArrayOf(0x42)
                )) {
                    zip.putNextEntry(ZipEntry(name))
                    zip.write(bytes)
                    zip.closeEntry()
                }
            }
        }.toByteArray()
        val apk = ApkStructureInspector().inspect(ByteArrayInputStream(file))
        val dex = DexHeaderInspector().inspect(ByteArrayInputStream(file))
        val zip = ZipInspector().inspect(ByteArrayInputStream(file))
        assertTrue(apk is ApkStructureInspector.Result.Complete)
        assertTrue(dex is DexHeaderInspector.Result.Complete)
        assertTrue(zip is ZipInspector.Result.Complete)
        val apkSummary = (apk as ApkStructureInspector.Result.Complete).summary
        val dexSummary = (dex as DexHeaderInspector.Result.Complete).summary
        val zipSummary = (zip as ZipInspector.Result.Complete).summary
        assertTrue(apkSummary.unsafePaths > 0)
        assertTrue(dexSummary.invalidHeaders > 0)
        assertTrue(zipSummary.unsafeNames > 0)
        val score = ExperimentalApkStructureModel.classify(
            ThreatFeatureVector.from(apk, dex, zip))
        assertTrue("Malformed archive should still produce bounded structural evidence",
            score is ThreatModel.Prediction.Scored)
        assertTrue((score as ThreatModel.Prediction.Scored).riskProbability > 0.8f)

        val omitted = ExperimentalApkStructureModel.classify(
            ThreatFeatureVector.from(apk, null, zip))
        assertTrue("Missing DEX analysis must not become an all-clear score",
            omitted is ThreatModel.Prediction.Unavailable)
    }
}
