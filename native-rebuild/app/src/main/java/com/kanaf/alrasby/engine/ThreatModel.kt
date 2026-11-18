package com.kanaf.alrasby.engine

/**
 * Contract for an independently validated, on-device classifier.
 * A classifier must be packaged with a compatible schema and validated weights.
 * No trained model is distributed yet.
 */
interface ThreatModel {
    val modelVersion: String
    val featureSchemaVersion: Int
    fun classify(features: ThreatFeatureVector): Prediction

    sealed interface Prediction {
        data class Scored(val riskProbability: Float, val modelVersion: String) : Prediction {
            init { require(riskProbability.isFinite() && riskProbability in 0f..1f) }
        }
        data class Unavailable(val reason: String) : Prediction
    }
}

object UnavailableThreatModel : ThreatModel {
    override val modelVersion = "not-installed"
    override val featureSchemaVersion = 1
    override fun classify(features: ThreatFeatureVector): ThreatModel.Prediction =
        ThreatModel.Prediction.Unavailable(
            if (!features.hasAnyObservation()) "no-observations" else "model-not-installed"
        )
}
