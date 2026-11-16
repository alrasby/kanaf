package com.kanaf.alrasby.engine

import org.junit.Assert.*
import org.junit.Test

/** Trained fixture score is structural only and never a malware verdict. */
class ExperimentalApkStructureModelTest {
    private fun vector(unsafe: Int = 0, invalid: Int = 0, zipUnsafe: Int = 0) =
        ThreatFeatureVector(
            apkDexCount = 5, apkNativeLibraryCount = 11, apkUnsafePathCount = unsafe,
            dexInvalidHeaderCount = invalid, zipUnsafeNameCount = zipUnsafe,
            zipEntryCount = 169, zipExpandedBytes = 51441611L
        )

    @Test fun realApkBaselineAndMutatedStructuralFixtureAreDistinguishable() {
        val baseline = ExperimentalApkStructureModel.classify(vector())
            as ThreatModel.Prediction.Scored
        val changed = ExperimentalApkStructureModel.classify(vector(2, 1, 1))
            as ThreatModel.Prediction.Scored
        assertTrue(baseline.riskProbability < .1f)
        assertTrue(changed.riskProbability > .9f)
        assertEquals("apk-structure-fixture-v1", baseline.modelVersion)
    }

    @Test fun absentEvidenceNeverMeansZeroFaults() {
        val verdict = ExperimentalApkStructureModel.classify(
            vector().copy(zipExpandedBytes = null))
        assertTrue(verdict is ThreatModel.Prediction.Unavailable)
    }
}
