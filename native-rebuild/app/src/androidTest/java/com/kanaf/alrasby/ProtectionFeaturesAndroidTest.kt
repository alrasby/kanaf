package com.kanaf.alrasby

import android.content.Intent
import android.net.Uri
import androidx.compose.ui.test.*
import androidx.compose.ui.semantics.getOrNull
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.test.platform.app.InstrumentationRegistry
import com.kanaf.alrasby.engine.*
import org.junit.After
import org.junit.Assert.*
import org.junit.Rule
import org.junit.Test

/** UI/data integration on Android, without installing or executing malware. */
class ProtectionFeaturesAndroidTest {
    @get:Rule val rule = createAndroidComposeRule<MainActivity>()
    private val context get() = InstrumentationRegistry.getInstrumentation().targetContext

    @After fun resetDiagnostics() {
        DnsDiagnosticPreferences.setEnabled(context, false)
        DnsDiagnosticPreferences.setAllowed(context, emptySet())
    }

    @Test fun healthScreenReflectsActualSignedDatabaseAndUpdateConfiguration() {
        rule.onNodeWithTag("nav_protection").performScrollTo().performClick()
        rule.onNodeWithTag("protection_health_title").assertExists()
        rule.waitUntil(15_000) {
            rule.onAllNodesWithTag("protection_health_summary").fetchSemanticsNodes()
                .any { node -> node.config.getOrNull(androidx.compose.ui.semantics.SemanticsProperties.Text)
                    ?.any { it.text.contains("v1") } == true }
        }
        rule.onNodeWithTag("auto_rule_updates_switch").assertIsOff()
        val status = SignatureRepository(context).status()
        assertTrue(status.version >= 1)
        assertEquals(30, status.count)
        assertTrue(ThreatRuleUpdater().availability().configured)
    }

    @Test fun dnsDiagnosticsRequireOptInAndLocalExceptionsCanBeAdded() {
        DnsDiagnosticPreferences.setEnabled(context, false)
        DnsDiagnosticPreferences.setAllowed(context, emptySet())
        rule.onNodeWithTag("open_dns_page").performScrollTo().performClick()
        rule.onNodeWithTag("dns_diagnostics_switch").performScrollTo().assertIsOff().performClick()
        assertTrue(DnsActivityLog.enabled)
        rule.onNodeWithTag("dns_exception_input").performScrollTo().performTextInput("example.com")
        rule.onNodeWithTag("dns_exception_add").performScrollTo().performClick()
        assertTrue("Local exception was not saved", "example.com" in DnsActivityLog.allowed())
        DnsActivityLog.record("host.example.com", "local test", "control")
        assertEquals(1, DnsActivityLog.snapshot().size)
        rule.onNodeWithTag("dns_diagnostics_switch").performScrollTo().performClick()
        assertTrue(DnsActivityLog.snapshot().isEmpty())
    }

    @Test fun androidPackagePermissionAndSigningEvidenceCanBeRead() {
        val snapshot = PackageBaseline.snapshot(context, context.packageName)
        assertTrue(snapshot.certificates.isNotEmpty())
        assertTrue(snapshot.permissions.contains("android.permission.INTERNET"))
        val privacy = PrivacyAudit.load(context, context.packageName)
        assertTrue(privacy.any { it.name == "android.permission.MANAGE_EXTERNAL_STORAGE" })
        val change = PackageBaseline.compare(snapshot, snapshot, false)
        assertFalse(change.unverifiedSignerChange)
        assertTrue(change.addedPermissions.isEmpty())
    }

    @Test fun liveSignedHttpsUpdateCanBeRepeatedWithoutRollbackOrReplacingKeys() {
        val before = SignatureRepository(context).status()
        val first = ThreatRuleUpdater().update(context)
        val second = ThreatRuleUpdater().update(context)
        val after = SignatureRepository(context).status()
        assertTrue(first >= before.version)
        assertEquals(first, second)
        assertEquals(second, after.version)
        assertEquals(before.sha256, after.sha256)
    }

    @Test fun sharedUnreadableFileOpensItsReportAndNeverReceivesASafetyVerdict() {
        val intent = Intent(Intent.ACTION_SEND).apply {
            type = "application/octet-stream"
            putExtra(Intent.EXTRA_STREAM, Uri.parse("content://com.kanaf.missing-provider/no-file"))
        }
        // Exercise the framework callback on the scenario-owned Activity;
        // opening another task would leave ActivityScenario tracking a paused parent.
        rule.runOnUiThread {
            InstrumentationRegistry.getInstrumentation().callActivityOnNewIntent(rule.activity, intent)
        }
        rule.waitUntil(30_000) {
            rule.onAllNodesWithTag("file_scan_result").fetchSemanticsNodes().any { node ->
                node.config.getOrNull(androidx.compose.ui.semantics.SemanticsProperties.Text)?.any {
                    it.text.contains("incomplete", true) || it.text.contains("غير مكتمل") ||
                        it.text.contains("Could not complete") || it.text.contains("تعذر إكمال")
                } == true
            }
        }
        rule.onNodeWithTag("file_scan_result").assertExists()
    }
    @Test fun installEventActuallyScansAccessiblePackageFilesAndWritesAReport() {
        val wasEnabled = ProtectionControl.installWatchEnabled(context)
        try {
            ProtectionControl.setInstallWatch(context, true)
            ProtectionControl.saveInstallResult(context, "")
            PackageChangeReceiver().onReceive(context, Intent(Intent.ACTION_PACKAGE_ADDED,
                Uri.parse("package:" + context.packageName)))
            val started = android.os.SystemClock.elapsedRealtime()
            var report = ""
            while (android.os.SystemClock.elapsedRealtime() - started < 120_000L) {
                report = ProtectionControl.lastInstallResult(context)
                if (report.isNotBlank()) break
                Thread.sleep(200)
            }
            assertTrue("No actual install-scan result: $report", report.contains("APK files checked="))
            assertFalse("Worker did not scan any APK: $report", report.contains("APK files checked=0;"))
            assertTrue(report.contains("incomplete="))
        } finally {
            ProtectionControl.setInstallWatch(context, wasEnabled)
        }
    }

}
