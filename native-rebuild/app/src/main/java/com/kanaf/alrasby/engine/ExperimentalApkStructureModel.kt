package com.kanaf.alrasby.engine

import kotlin.math.exp
import kotlin.math.ln

/**
 * Local experimental structural-anomaly model, NOT a malware classifier.
 * Trained on 12,000 generated structural fixtures, evaluated on 3,000 separate
 * fixtures; checked against an actual Kanaf debug APK structural baseline.
 * No real-world malicious ground-truth APK labels were used.
 */
object ExperimentalApkStructureModel : ThreatModel {
    override val modelVersion = "apk-structure-fixture-v1"
    override val featureSchemaVersion = 1
    private const val BIAS = -0.45171988984787753
    private val WEIGHTS = doubleArrayOf(
        -0.27664860827606197, -0.008609034959379622, 6.906597072929637,
        7.737452012358553, 7.0038476022166325, -0.0601200244770211,
        -0.13069583673444082
    )

    override fun classify(features: ThreatFeatureVector): ThreatModel.Prediction {
        if (features.schemaVersion != 1) {
            return ThreatModel.Prediction.Unavailable("pilot-schema-mismatch")
        }
        val input = listOf(
            features.apkDexCount?.toLong(), features.apkNativeLibraryCount?.toLong(),
            features.apkUnsafePathCount?.toLong(), features.dexInvalidHeaderCount?.toLong(),
            features.zipUnsafeNameCount?.toLong(), features.zipEntryCount?.toLong(),
            features.zipExpandedBytes
        )
        if (input.any { it == null }) {
            return ThreatModel.Prediction.Unavailable("pilot-inspection-incomplete")
        }
        val transformed = input.map { ln(1.0 + it!!.coerceAtMost(1_000_000_000L)) }
        val raw = WEIGHTS.indices.fold(BIAS) { sum, i ->
            sum + WEIGHTS[i] * transformed[i]
        }
        if (!raw.isFinite()) {
            return ThreatModel.Prediction.Unavailable("pilot-nonfinite")
        }
        val score = (1.0 / (1.0 + exp(-raw.coerceIn(-40.0, 40.0)))).toFloat()
        return ThreatModel.Prediction.Scored(score, modelVersion)
    }
}
