package com.kanaf.alrasby.engine

import org.junit.Assert.assertEquals
import org.junit.Test

class ThreatFamilyTest {
    @Test fun categoriesRequireSpecificSignatureFamily() {
        assertEquals(ThreatFamily.Kind.BACKDOOR, ThreatFamily.classify("Backdoor.Android.Agent"))
        assertEquals(ThreatFamily.Kind.RANSOMWARE, ThreatFamily.classify("Ransomware:Foo"))
        assertEquals(ThreatFamily.Kind.TROJAN, ThreatFamily.classify("Trojan-Android"))
        assertEquals(ThreatFamily.Kind.UNCLASSIFIED, ThreatFamily.classify("safe.backdoor.claim"))
        assertEquals(ThreatFamily.Kind.UNCLASSIFIED, ThreatFamily.classify("suspicious.apk"))
    }

    @Test fun eicarCannotBeReportedAsRealMalware() {
        assertEquals(ThreatFamily.Kind.TEST_SAMPLE, ThreatFamily.classify("Kanaf.EICAR.Test"))
        assertEquals(ThreatFamily.Kind.TEST_SAMPLE, ThreatFamily.classify("Kanaf_EICAR_Test"))
        assertEquals("Harmless test sample", ThreatFamily.label("Kanaf.EICAR.Test", false))
    }

    @Test fun labelsAreBilingualAndUnknownDoesNotGuess() {
        assertEquals("باب خلفي", ThreatFamily.label("Backdoor.Android.Agent", true))
        assertEquals("Unclassified signature label", ThreatFamily.label("unknown", false))
    }
}
