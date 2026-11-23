package com.kanaf.alrasby

import androidx.lifecycle.ViewModelProvider
import androidx.test.core.app.ActivityScenario
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
    @Test fun activeDeviceScanKeepsItsOwnerAfterActivityRecreation() {
        ActivityScenario.launch(MainActivity::class.java).use { scenario ->
            lateinit var session: DeviceScanSession
            scenario.onActivity { activity ->
                session = ViewModelProvider(activity)[DeviceScanSession::class.java]
                session.start(includeSharedStorage = false)
                assertTrue(session.state.value.active)
            }
            scenario.recreate()
            scenario.onActivity { replacement ->
                assertSame(session, ViewModelProvider(replacement)[DeviceScanSession::class.java])
                assertTrue(session.state.value.active || session.state.value.result != null)
                session.stop()
            }
        }
    }

    @Test fun interruptionReportRestoresLastPhaseCounterAndOriginalBuild() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val prefs = context.getSharedPreferences("device_scan_checkpoint", 0)
        prefs.edit().clear().putInt("attempted", 1224).putString("phase", "files")
            .putString("build", "previous").commit()
        try {
            ActivityScenario.launch(MainActivity::class.java).use { scenario ->
                scenario.onActivity { activity ->
                    val session = ViewModelProvider(activity)[DeviceScanSession::class.java]
                    val interruption = checkNotNull(session.state.value.interruption)
                    assertFalse(session.state.value.active)
                    assertEquals(1224, interruption.attempted)
                    assertTrue(interruption.description().en.contains("shared files"))
                    assertTrue(interruption.description().en.contains("Build previous"))
                }
            }
        } finally {
            prefs.edit().clear().commit()
        }
    }

    @Test fun appOnlyScanIsBoundedAndHonestAboutUnavailableNativeChecks() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val started = android.os.SystemClock.elapsedRealtime()
        val updates = mutableListOf<AutomaticDeviceScan.Progress>()
        val result = AutomaticDeviceScan().run(
            context, includeSharedStorage = false,
            progress = updates::add,
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
        assertEquals("inventory", updates.first().phase)
        assertEquals("apps", updates[1].phase)
        assertEquals(result.installedApps, updates[1].applications)
        assertEquals(0, updates[1].appApks)
        assertEquals(1, updates.first { it.appApks > 0 }.appApks)
        assertTrue(result.incomplete <= result.appApksAttempted)
        assertTrue(result.incompleteReasons.values.all { it <= result.incomplete })
        assertEquals("done", updates.last().phase)
    }
}
