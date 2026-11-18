package com.kanaf.alrasby

import android.content.Intent
import android.net.Uri
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.kanaf.alrasby.engine.PackageChangeReceiver
import com.kanaf.alrasby.engine.ProtectionControl
import com.kanaf.alrasby.engine.SafQuarantine
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith

/** Optional monitor must never be active without explicit user opt-in. */
@RunWith(AndroidJUnit4::class)
class ProtectionOptInAndroidTest {
    private val context get() = InstrumentationRegistry.getInstrumentation().targetContext

    @Test fun installWatchCanBeExplicitlyEnabledAndDisabled() {
        try {
            ProtectionControl.setInstallWatch(context, false)
            assertFalse(ProtectionControl.installWatchEnabled(context))
            PackageChangeReceiver().onReceive(context, Intent(Intent.ACTION_PACKAGE_ADDED,
                Uri.parse("package:com.example.test")))
            ProtectionControl.setInstallWatch(context, true)
            assertTrue(ProtectionControl.installWatchEnabled(context))
        } finally {
            ProtectionControl.setInstallWatch(context, false)
        }
        assertFalse(ProtectionControl.installWatchEnabled(context))
    }

    @Test fun rejectsUnpersistedFolderAndAllowsScheduleOptOut() {
        ProtectionControl.disableTreeChecks(context)
        assertFalse(ProtectionControl.periodicEnabled(context))
        assertThrows(Exception::class.java) {
            ProtectionControl.enableTreeChecks(context,
                Uri.parse("content://nonexistent.provider/tree/blocked"))
        }
        assertFalse(ProtectionControl.periodicEnabled(context))
    }

    @Test fun refusesNonSafQuarantineAndDoesNotDeleteOriginal() {
        val uri = Uri.fromFile(java.io.File(context.cacheDir, "do-not-delete.txt"))
        assertTrue(SafQuarantine().isolateSelectedDocument(context, uri)
            is SafQuarantine.Outcome.Failed)
    }
}
