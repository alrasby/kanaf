package com.kanaf.alrasby.engine

import org.junit.Assert.*
import org.junit.Test

class ThreatModelTest {
    @Test fun missingModelCannotPretendToClassify() {
        val vector = ThreatFeatureVector.from(null, null, null)
        val result = UnavailableThreatModel.classify(vector)
        assertEquals("no-observations", (result as ThreatModel.Prediction.Unavailable).reason)
    }
    @Test fun invalidProbabilitiesAreRejected() {
        for (score in listOf(-0.1f, 1.1f, Float.NaN, Float.POSITIVE_INFINITY)) {
            try {
                ThreatModel.Prediction.Scored(score, "test")
                fail("Invalid probability must fail: $score")
            } catch (_: IllegalArgumentException) {
                // Expected
            }
        }
    }
}
