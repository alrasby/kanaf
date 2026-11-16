package com.kanaf.alrasby

import android.content.pm.ApplicationInfo
import android.security.NetworkSecurityPolicy
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.kanaf.alrasby.engine.ThreatFeatureVector
import com.kanaf.alrasby.engine.ThreatModel
import com.kanaf.alrasby.engine.UnavailableThreatModel
import com.kanaf.alrasby.engine.VerifiedLinearThreatModel
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith

/** Production builds cannot pretend unsigned test weights are malware AI. */
@RunWith(AndroidJUnit4::class)
class KanafAiIntegrationAndroidTest {
    @Test fun defaultBuildDisablesUntrainedAi() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        if (BuildConfig.KANAF_MODEL_PUBLIC_KEY_BASE64.isNotBlank()) return
        assertSame(UnavailableThreatModel, VerifiedLinearThreatModel.load(context))
        val features = ThreatFeatureVector(
            apkDexCount = 2, apkNativeLibraryCount = 0,
            apkUnsafePathCount = 0, dexInvalidHeaderCount = 0,
            zipUnsafeNameCount = 0, zipEntryCount = 4, zipExpandedBytes = 12000
        )
        val result = VerifiedLinearThreatModel.load(context).classify(features)
        assertTrue(result is ThreatModel.Prediction.Unavailable)
        assertEquals("model-not-installed", (result as ThreatModel.Prediction.Unavailable).reason)
    }

    @Test fun compiledStructuralPilotExecutesOnAndroidWithoutMalwareClaims() {
        val model = com.kanaf.alrasby.engine.ExperimentalApkStructureModel
        fun observed(unsafe: Int) = ThreatFeatureVector(
            apkDexCount = 5, apkNativeLibraryCount = 11,
            apkUnsafePathCount = unsafe, dexInvalidHeaderCount = 0,
            zipUnsafeNameCount = unsafe, zipEntryCount = 169,
            zipExpandedBytes = 51441611L
        )
        val baseline = model.classify(observed(0))
        val fault = model.classify(observed(3))
        assertTrue(baseline is ThreatModel.Prediction.Scored)
        assertTrue(fault is ThreatModel.Prediction.Scored)
        assertTrue((baseline as ThreatModel.Prediction.Scored).riskProbability <
            (fault as ThreatModel.Prediction.Scored).riskProbability)
        assertEquals("apk-structure-fixture-v1", (fault as ThreatModel.Prediction.Scored).modelVersion)
        assertTrue(model.classify(observed(0).copy(apkDexCount = null))
            is ThreatModel.Prediction.Unavailable)
    }

    @Test fun backupAndCleartextRemainDisabled() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        assertEquals(0, context.applicationInfo.flags and ApplicationInfo.FLAG_ALLOW_BACKUP)
        assertFalse(NetworkSecurityPolicy.getInstance().isCleartextTrafficPermitted())
    }
}
