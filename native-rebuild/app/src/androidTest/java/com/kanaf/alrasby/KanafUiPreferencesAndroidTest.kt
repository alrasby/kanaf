package com.kanaf.alrasby

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith

/** Real Android preferences: persisted language, tab hiding and immovable scan. */
@RunWith(AndroidJUnit4::class)
class KanafUiPreferencesAndroidTest {
    private val context get() = InstrumentationRegistry.getInstrumentation().targetContext

    @Test fun languageAndVisibilityPersistAcrossInstances() {
        val settings = KanafUiPreferences(context)
        try {
            settings.setLanguage(KanafLanguage.ARABIC)
            settings.setSectionVisible(KanafSection.LINKS, false)
            settings.setSectionVisible(KanafSection.VAULT, false)
            val reloaded = KanafUiPreferences(context)
            assertEquals(KanafLanguage.ARABIC, reloaded.language())
            assertTrue(reloaded.hiddenSections().contains("links"))
            assertTrue(reloaded.hiddenSections().contains("vault"))
            assertFalse(reloaded.hiddenSections().contains("scan"))
            reloaded.setLanguage(KanafLanguage.ENGLISH)
            assertEquals(KanafLanguage.ENGLISH, settings.language())
            reloaded.setSectionVisible(KanafSection.LINKS, true)
            assertFalse(KanafUiPreferences(context).hiddenSections().contains("links"))
            assertThrows(IllegalArgumentException::class.java) {
                reloaded.setSectionVisible(KanafSection.SCAN, false)
            }
        } finally {
            settings.setLanguage(KanafLanguage.SYSTEM)
            KanafSection.OPTIONAL.forEach { settings.setSectionVisible(it, true) }
        }
    }
}
