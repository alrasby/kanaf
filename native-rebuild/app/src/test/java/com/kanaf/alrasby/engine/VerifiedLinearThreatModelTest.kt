package com.kanaf.alrasby.engine

import java.security.KeyPairGenerator
import java.security.Signature
import java.util.Base64
import org.junit.Assert.*
import org.junit.Test

class VerifiedLinearThreatModelTest {
    private val pair = KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }
        .generateKeyPair()
    private val valid = listOf(
        "KanafML-1", "1", "test-validated-v1", "0.0",
        "0.1", "-0.1", "0.5", "0.5", "0.5", "0.05", "0.01",
        "0.93", "0.003", "0.91", "6000", "3000", "3000"
    ).joinToString("\n", postfix = "\n").toByteArray(Charsets.US_ASCII)

    private fun signature(bytes: ByteArray): String {
        val signer = Signature.getInstance("SHA256withRSA")
        signer.initSign(pair.private)
        signer.update(bytes)
        return Base64.getEncoder().encodeToString(signer.sign())
    }
    private fun load(data: ByteArray = valid, proof: String = signature(data)) =
        VerifiedLinearThreatModel.parseVerified(data, proof, pair.public.encoded)

    @Test fun validatedSignedWeightsScoreCompleteFeatureVector() {
        val model = load()
        val values = ThreatFeatureVector(
            apkDexCount = 2, apkNativeLibraryCount = 1,
            apkUnsafePathCount = 0, dexInvalidHeaderCount = 0,
            zipUnsafeNameCount = 0, zipEntryCount = 12, zipExpandedBytes = 5000
        )
        val score = model.classify(values)
        assertTrue(score is ThreatModel.Prediction.Scored)
        assertEquals("test-validated-v1", (score as ThreatModel.Prediction.Scored).modelVersion)
        assertTrue(score.riskProbability in 0f..1f)
    }

    @Test fun incompleteInputIsNotImputedAsSafeZero() {
        val model = load()
        val values = ThreatFeatureVector(
            apkDexCount = null, apkNativeLibraryCount = 1,
            apkUnsafePathCount = 0, dexInvalidHeaderCount = 0,
            zipUnsafeNameCount = 0, zipEntryCount = 12, zipExpandedBytes = 5000
        )
        assertTrue(model.classify(values) is ThreatModel.Prediction.Unavailable)
    }

    @Test fun rejectsModelTamperingAndWrongSigningKey() {
        assertThrows(Exception::class.java) { load(valid.copyOf().also { it[9] = 65 }) }
        val other = KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }
            .generateKeyPair()
        assertThrows(Exception::class.java) {
            VerifiedLinearThreatModel.parseVerified(valid, signature(valid), other.public.encoded)
        }
    }

    @Test fun evaluationGateRejectsBadFprEvenWithValidSignature() {
        val bad = valid.toString(Charsets.US_ASCII).replace("\n0.003\n", "\n0.03\n")
            .toByteArray(Charsets.US_ASCII)
        assertThrows(IllegalArgumentException::class.java) { load(bad) }
    }

    @Test fun evaluationGateRejectsInsufficientIndependentSamples() {
        val bad = valid.toString(Charsets.US_ASCII).replace("\n6000\n", "\n4000\n")
            .toByteArray(Charsets.US_ASCII)
        assertThrows(IllegalArgumentException::class.java) { load(bad) }
    }
}
