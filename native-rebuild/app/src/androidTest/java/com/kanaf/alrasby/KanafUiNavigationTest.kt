package com.kanaf.alrasby

import androidx.compose.ui.semantics.SemanticsActions
import androidx.compose.ui.text.TextLayoutResult
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollTo
import androidx.compose.ui.test.performSemanticsAction
import androidx.compose.ui.unit.sp
import androidx.test.platform.app.InstrumentationRegistry
import android.os.Build
import org.junit.After
import org.junit.Assert.assertFalse
import org.junit.Assert.assertEquals
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
        rule.onNodeWithText("Kanaf AI — on-device analysis").assertExists()
        rule.onNodeWithTag("kanaf_ai_status").assertExists()
        rule.onNodeWithText("About Kanaf").assertExists()
        rule.onNodeWithText("Made with ❤️ By NabdhServ.Net").assertExists()
        rule.onNodeWithTag("lang_ar").performScrollTo().performClick()
        rule.onNodeWithText("اللغة والعرض").assertExists()
        rule.onNodeWithText("حول كنف").assertExists()
        rule.onNodeWithTag("lang_en").performScrollTo().performClick()
        rule.onNodeWithText("Language & display").assertExists()
        rule.onNodeWithTag("settings_button").performClick()
        rule.onNodeWithTag("nav_scan").assertExists()
        rule.onNodeWithText("Made with ❤️ By NabdhServ.Net").assertDoesNotExist()
    }

    @Test fun oneTapHomeAndIndependentDnsPageDoNotCrowdScreen() {
        rule.onNodeWithTag("device_scan_button").assertExists()
        rule.onNodeWithTag("open_dns_page").assertExists()
        rule.onNodeWithTag("dns_filter_switch").assertDoesNotExist()
        rule.onNodeWithTag("open_dns_page").performScrollTo().performClick()
        // Android 8 has no system Private DNS; it was added in Android 9.
        if (Build.VERSION.SDK_INT >= 28) {
            rule.onNodeWithTag("dns_system_off").assertExists()
            rule.onNodeWithTag("dns_system_auto").assertExists()
        }
        if (BuildConfig.KANAF_PLAY_DNS_SECURITY_ONLY) {
            rule.onNodeWithTag("dns_provider_security_cloudflare-dns_com").assertExists()
            rule.onNodeWithTag("dns_provider_switch_security_cloudflare-dns_com").assertExists()
            rule.onNodeWithTag("dns_provider_dns_adguard-dns_com").assertDoesNotExist()
        } else {
            rule.onNodeWithTag("dns_provider_dns_adguard-dns_com").assertExists()
            rule.onNodeWithTag("dns_provider_family_adguard-dns_com").assertExists()
            rule.onNodeWithTag("dns_provider_switch_dns_adguard_com").assertExists()
            rule.onNodeWithTag("dns_provider_switch_dns_adguard-dns_com").assertExists()
            rule.onNodeWithTag("dns_provider_switch_family_adguard-dns_com").assertExists()
        }
        rule.onNodeWithTag("dns_add_quick_tile").assertExists()
        rule.onNodeWithTag("dns_filter_switch").assertExists()
        rule.onNodeWithTag("dns_refresh_stats").assertExists()
        rule.onNodeWithTag("dns_check_coverage").assertExists()
        rule.onNodeWithTag("dns_advanced_options").assertExists()
    }

    @Test fun oneTapScanExplainsFilesAccessWithoutForcingIt() {
        rule.onNodeWithTag("device_scan_button").performClick()
        rule.onNodeWithTag("scan_apps_only").assertExists()
        rule.onNodeWithTag("grant_files_for_auto_scan").assertExists()
    }

    @Test fun featureDescriptionsHaveCompactReadableTextInBothLanguages() {
        fun assertDescription(text: String) {
            val layouts = mutableListOf<TextLayoutResult>()
            rule.onNodeWithText(text, substring = true).performScrollTo()
                .performSemanticsAction(SemanticsActions.GetTextLayoutResult) { it(layouts) }
            val layout = layouts.single()
            assertEquals(13.sp, layout.layoutInput.style.fontSize)
            assertEquals(19.sp, layout.layoutInput.style.lineHeight)
            assertFalse(layout.hasVisualOverflow)
        }

        for (arabic in listOf(false, true)) {
            rule.onNodeWithTag("settings_button").performClick()
            rule.onNodeWithTag(if (arabic) "lang_ar" else "lang_en").performScrollTo().performClick()
            rule.onNodeWithTag("settings_button").performClick()
            assertDescription(if (arabic) "افحص التطبيقات والملفات المتاحة بضغطة واحدة"
                else "One-tap inspection of installed apps")
            rule.onNodeWithTag("nav_engines").performScrollTo().performClick()
            assertDescription(if (arabic) "اختبر ClamAV وYARA-X باستخدام عينة"
                else "Run the native ClamAV and YARA-X engines")
            rule.onNodeWithTag("settings_button").performClick()
        }
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
        rule.onNodeWithTag("nav_scan").assertExists()
        rule.onNodeWithTag("nav_links").assertDoesNotExist()
        rule.onNodeWithTag("settings_button").performClick()
        rule.onNodeWithTag("nav_switch_links").performScrollTo().performClick()
        rule.onNodeWithTag("settings_button").performClick()
        rule.onNodeWithTag("nav_links").assertExists()
    }
}
