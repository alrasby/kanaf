package com.kanaf.alrasby.engine

import android.content.Context
import com.kanaf.alrasby.BuildConfig
import java.security.KeyFactory
import java.security.MessageDigest
import java.security.Signature
import java.security.spec.X509EncodedKeySpec
import java.util.Base64
import kotlin.math.exp
import kotlin.math.ln

/**
 * Lightweight audited-model INFERENCE only. A trained model can be enabled
 * after a publisher signs its exact bytes with a key pinned at build time.
 * The default build has neither a key nor model weights => Unavailable.
 * This cannot replace a malware-signature detector or claim a clean verdict.
 */
class VerifiedLinearThreatModel private constructor(
    override val modelVersion: String,
    private val bias: Double,
    private val weights: List<Double>
) : ThreatModel {
    override val featureSchemaVersion = 1

    override fun classify(features: ThreatFeatureVector): ThreatModel.Prediction {
        if (features.schemaVersion != featureSchemaVersion) {
            return ThreatModel.Prediction.Unavailable("model-schema-mismatch")
        }
        val inputs = listOf(
            features.apkDexCount?.toLong(),
            features.apkNativeLibraryCount?.toLong(),
            features.apkUnsafePathCount?.toLong(),
            features.dexInvalidHeaderCount?.toLong(),
            features.zipUnsafeNameCount?.toLong(),
            features.zipEntryCount?.toLong(),
            features.zipExpandedBytes
        )
        // Missing structure is UNKNOWN and MUST NOT be converted to zero.
        if (inputs.any { it == null }) {
            return ThreatModel.Prediction.Unavailable("incomplete-feature-vector")
        }
        val transformed = inputs.map { ln(1.0 + (it ?: 0L).coerceAtMost(1_000_000_000L)) }
        val raw = weights.indices.fold(bias) { score, i ->
            score + weights[i] * transformed[i]
        }
        if (!raw.isFinite()) return ThreatModel.Prediction.Unavailable("model-nonfinite-score")
        val probability = (1.0 / (1.0 + exp(-raw.coerceIn(-40.0, 40.0)))).toFloat()
        return ThreatModel.Prediction.Scored(probability, modelVersion)
    }

    companion object {
        private val versionPattern = Regex("[A-Za-z0-9_.-]{1,48}")
        /**
         * Signed ASCII format has exact LF lines and no trailing ambiguity:
         * KanafML-1, schema=1, model version, bias, 7 weights, then
         * AUC, FPR, recall, test sample count, benign count, malicious count.
         * Publisher-attested validation stats need independent audit before release.
         */
        internal fun parseVerified(
            bytes: ByteArray, signatureBase64: String, publicKeyDer: ByteArray
        ): VerifiedLinearThreatModel {
            require(bytes.isNotEmpty() && bytes.size <= 4096) { "model-size-invalid" }
            val verifier = Signature.getInstance("SHA256withRSA")
            verifier.initVerify(
                KeyFactory.getInstance("RSA").generatePublic(X509EncodedKeySpec(publicKeyDer))
            )
            verifier.update(bytes)
            require(verifier.verify(Base64.getDecoder().decode(signatureBase64))) {
                "model-signature-invalid"
            }
            val source = bytes.toString(Charsets.US_ASCII)
            require(source.toByteArray(Charsets.US_ASCII).contentEquals(bytes)) {
                "model-not-ascii"
            }
            require(source.endsWith("\n") && !source.contains("\r")) { "model-format-invalid" }
            val lines = source.dropLast(1).split('\n')
            require(lines.size == 17 && lines[0] == "KanafML-1" && lines[1] == "1") {
                "model-format-invalid"
            }
            val version = lines[2]
            require(versionPattern.matches(version)) { "model-version-invalid" }
            fun numeric(i: Int): Double {
                require(lines[i].matches(Regex("-?[0-9]+(?:\\.[0-9]+)?"))) {
                    "model-number-invalid"
                }
                val value = lines[i].toDouble()
                require(value.isFinite()) { "model-number-nonfinite" }
                return value
            }
            val bias = numeric(3)
            val weights = (4..10).map(::numeric)
            require((weights + bias).all { it in -100.0..100.0 }) {
                "model-weights-out-of-bounds"
            }
            val auc = numeric(11)
            val fpr = numeric(12)
            val recall = numeric(13)
            val heldOut = lines[14].toInt()
            val benign = lines[15].toInt()
            val malicious = lines[16].toInt()
            require(heldOut >= 5000 && benign >= 2000 && malicious >= 2000 &&
                benign + malicious == heldOut && auc >= 0.90 &&
                fpr in 0.0..0.005 && recall in 0.85..1.0) {
                "model-independent-validation-gate-failed"
            }
            return VerifiedLinearThreatModel(version, bias, weights)
        }

        fun load(context: Context): ThreatModel {
            val publicKey = BuildConfig.KANAF_MODEL_PUBLIC_KEY_BASE64
            if (publicKey.isBlank()) return UnavailableThreatModel
            return try {
                val bytes = context.assets.open("validated_model.txt").use { it.readBytes() }
                val signature = context.assets.open("validated_model.sig").bufferedReader()
                    .use { it.readText().trim() }
                parseVerified(bytes, signature, Base64.getDecoder().decode(publicKey))
            } catch (_: Exception) {
                UnavailableThreatModel
            }
        }
    }
}
