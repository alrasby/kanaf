package com.kanaf.alrasby

import com.kanaf.alrasby.engine.AntivirusEngine
import com.kanaf.alrasby.engine.ProtectionAlerts
import com.kanaf.alrasby.engine.ScanEvidenceText
import java.util.Locale
import org.junit.Assert.*
import org.junit.Test

class KanafLocalizationTest {
    @Test fun bothVersionsOfResultsStayAvailableAfterLanguageChange() {
        val message = KanafMessage(
            "التحليل غير مكتمل", "Analysis incomplete"
        )
        assertEquals("التحليل غير مكتمل", message.displayed(KanafLanguage.ARABIC))
        assertEquals("Analysis incomplete", message.displayed(KanafLanguage.ENGLISH))
        val combined = KanafMessage.combine(listOf(message, KanafMessage.EMPTY,
            KanafMessage("لا تُثبت السلامة", "Safety not verified")))
        assertEquals(2, combined.en.lines().size)
        assertTrue(combined.ar.contains("لا تُثبت السلامة"))
    }

    @Test fun scheduledResultTranslatesWithoutChangingItsCounts() {
        val raw = "Scoped SHA-256: checked=7 matches=1 incomplete=2 truncated=false"
        val both = KanafMessage.fromScheduledStatus(raw)
        assertTrue(both.ar.contains("7"))
        assertTrue(both.ar.contains("2"))
        assertEquals(raw, both.en)
        assertTrue(KanafMessage.fromScheduledStatus(
            "INCOMPLETE: signature database unavailable"
        ).ar.contains("غير متاحة"))
    }

    @Test fun scanEvidenceNeverClaimsSafetyInEitherLanguage() {
        val result = AntivirusEngine.Verdict.Incomplete("read-failed")
        val english = ScanEvidenceText.hashLabel(result, 0, false, arabic = false)
        val arabic = ScanEvidenceText.hashLabel(result, 0, false, arabic = true)
        assertTrue(english.contains("incomplete", ignoreCase = true))
        assertTrue(arabic.contains("غير مكتمل"))
    }

    @Test fun optInAlertIsTranslatedWithoutExposingPackageOrFileName() {
        val english = ProtectionAlerts.localizedEvent(12004, false,
            "App review", "Review after installation")
        val arabic = ProtectionAlerts.localizedEvent(12004, true,
            "App review", "Review after installation")
        assertTrue(english.second.contains("Review"))
        assertTrue(arabic.second.contains("مراجعة"))
        assertFalse(arabic.second.contains("package:"))
    }
}
