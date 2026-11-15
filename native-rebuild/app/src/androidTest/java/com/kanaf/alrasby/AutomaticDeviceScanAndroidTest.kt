package com.kanaf.alrasby

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.kanaf.alrasby.engine.AutomaticDeviceScan
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Actual Android package enumeration and bounded APK access, not a UI mock.
 * Native scans intentionally disabled here; partial work must stay incomplete.
 */
@RunWith(AndroidJUnit4::class)
class AutomaticDeviceScanAndroidTest {
    @Test fun appOnlyScanIsBoundedAndHonestAboutUnavailableNativeChecks() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val started = android.os.SystemClock.elapsedRealtime()
        val result = AutomaticDeviceScan().run(
            context, includeSharedStorage = false,
            limits = AutomaticDeviceScan.Limits(
                apkFiles = 5, sharedFiles = 1, nativeChecks = 0,
                durationMs = 20_000L, hashBytes = 16L * 1024 * 1024
            )
        )
        assertTrue("Expected installed packages", result.installedApps > 0)
        assertTrue("Must attempt an APK", result.appApksAttempted > 0)
        assertEquals("No shared file reads without permission", 0, result.sharedFilesAttempted)
        assertFalse("App-only scan must not claim shared storage", result.sharedStorageGranted)
        assertEquals("Native engine deliberately unavailable", 0, result.nativeChecked)
        assertTrue("Unavailable engine must not become clean", result.incomplete > 0)
        assertTrue("App-only QA must be bounded", result.appApksAttempted <= 5)
        assertTrue("Bounded scan must terminate",
            android.os.SystemClock.elapsedRealtime() - started < 35_000L)
    }
}
