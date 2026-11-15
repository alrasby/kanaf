package com.kanaf.alrasby

import java.util.Locale
import org.junit.Assert.*
import org.junit.Test

class KanafLanguageTest {
    @Test fun systemModeResolvesArabicAndEnglishWithoutChangingSystemLocale() {
        assertEquals("ar", KanafLanguage.SYSTEM.resolvedLocale(Locale("ar", "OM")).language)
        assertEquals("en", KanafLanguage.SYSTEM.resolvedLocale(Locale("en", "US")).language)
        assertEquals("en", KanafLanguage.SYSTEM.resolvedLocale(Locale("fr", "FR")).language)
    }

    @Test fun manualLanguageOverridesSystemAndUnknownPreferencesFallbackSafely() {
        assertTrue(KanafLanguage.ARABIC.isArabic(Locale.ENGLISH))
        assertFalse(KanafLanguage.ENGLISH.isArabic(Locale("ar", "OM")))
        assertEquals(KanafLanguage.SYSTEM, KanafLanguage.fromStored("unsupported"))
        assertEquals(KanafLanguage.SYSTEM, KanafLanguage.fromStored(null))
    }

    @Test fun stableTabIdsCannotAccidentallyHideSettingsOrScan() {
        assertEquals("scan", KanafSection.SCAN.id)
        assertEquals(6, KanafSection.OPTIONAL.size)
        assertFalse(KanafSection.OPTIONAL.contains(KanafSection.SCAN))
        assertEquals(KanafSection.VAULT, KanafSection.fromId("vault"))
        assertNull(KanafSection.fromId("settings"))
        assertNull(KanafSection.fromId("about"))
    }
}
