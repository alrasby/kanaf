package com.kanaf.alrasby

import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollTo
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.After
import org.junit.Assert.assertFalse
import org.junit.Rule
import org.junit.Test

/** Actual Compose-screen regression: content, locale, navigation and footer. */
class KanafUiNavigationTest {
    @get:Rule val rule = createAndroidComposeRule<MainActivity>()

    @After fun resetPresentation() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val settings = KanafUiPreferences(context)
        settings.setLanguage(KanafLanguage.SYSTEM)
        KanafSection.OPTIONAL.forEach { settings.setSectionVisible(it, true) }
    }

    @Test fun footerAndAboutLiveOnlyInsideSettingsAndLanguageChangesImmediately() {
        rule.onNodeWithText("Made with ❤️ By NabdhServ.Net").assertDoesNotExist()
        rule.onNodeWithTag("settings_button").performClick()
        rule.onNodeWithTag("lang_en").performScrollTo().performClick()
        rule.onNodeWithText("Language & display").assertExists()
        rule.onNodeWithText("About Kanaf").assertExists()
        rule.onNodeWithText("Made with ❤️ By NabdhServ.Net").assertExists()
        rule.onNodeWithTag("lang_ar").performScrollTo().performClick()
        rule.onNodeWithText("اللغة والعرض").assertExists()
        rule.onNodeWithText("حول كنف").assertExists()
        rule.onNodeWithTag("lang_en").performScrollTo().performClick()
        rule.onNodeWithText("Language & display").assertExists()
        rule.onNodeWithTag("settings_button").performClick()
        rule.onNodeWithTag("more_features").performClick()
        rule.onNodeWithTag("nav_scan").assertExists()
        rule.onNodeWithText("Made with ❤️ By NabdhServ.Net").assertDoesNotExist()
    }

    @Test fun oneTapHomeAndIndependentDnsPageDoNotCrowdScreen() {
        rule.onNodeWithTag("device_scan_button").assertExists()
        rule.onNodeWithTag("open_dns_page").assertExists()
        rule.onNodeWithTag("dns_filter_switch").assertDoesNotExist()
        rule.onNodeWithTag("open_dns_page").performClick()
        rule.onNodeWithTag("dns_system_off").assertExists()
        rule.onNodeWithTag("dns_system_auto").assertExists()
        rule.onNodeWithTag("dns_add_provider").assertExists()
        rule.onNodeWithTag("dns_filter_switch").assertExists()
    }

    @Test fun advancedScanToolsMovedAwayFromHome() {
        rule.onNodeWithTag("home_native_engines_test").assertDoesNotExist()
        rule.onNodeWithTag("open_scan_tools").performClick()
        rule.onNodeWithTag("home_native_engines_test").assertExists()
        rule.onNodeWithTag("manual_file_scan").assertExists()
        rule.onNodeWithTag("request_storage_scan_access").assertExists()
    }

    @Test fun hideAndShowLinksTabWithoutHidingScanOrSettings() {
        rule.onNodeWithTag("settings_button").performClick()
        rule.onNodeWithTag("nav_switch_links").performScrollTo().performClick()
        val settings = KanafUiPreferences(
            InstrumentationRegistry.getInstrumentation().targetContext
        )
        assertFalse(settings.hiddenSections().isEmpty())
        rule.onNodeWithTag("settings_button").performClick()
        rule.onNodeWithTag("more_features").performClick()
        rule.onNodeWithTag("nav_scan").assertExists()
        rule.onNodeWithTag("nav_links").assertDoesNotExist()
        rule.onNodeWithTag("settings_button").performClick()
        rule.onNodeWithTag("nav_switch_links").performScrollTo().performClick()
        rule.onNodeWithTag("settings_button").performClick()
        rule.onNodeWithTag("nav_links").assertExists()
    }
}
