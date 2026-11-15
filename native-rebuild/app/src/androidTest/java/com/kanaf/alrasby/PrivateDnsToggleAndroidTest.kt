package com.kanaf.alrasby

import android.os.Build
import android.provider.Settings
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.kanaf.alrasby.engine.PrivateDnsCompatibility
import com.kanaf.alrasby.engine.PrivateDnsToggle
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Real Android system Settings.Global write with a CI-only external ADB grant.
 * No VPN or network service is started. The original DNS mode is restored.
 */
@RunWith(AndroidJUnit4::class)
class PrivateDnsToggleAndroidTest {
    @Test fun actualPrivilegedOffToAutoTransitionAndMarkerCleanup() {
        if (Build.VERSION.SDK_INT < 28) return
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val resolver = context.contentResolver
        val original = Settings.Global.getString(resolver, "private_dns_mode")
        assertTrue("CI must install and externally grant WRITE_SECURE_SETTINGS",
            PrivateDnsToggle.granted(context))
        try {
            assertTrue(Settings.Global.putString(
                resolver, "private_dns_mode", "opportunistic"))
            assertEquals(PrivateDnsCompatibility.Mode.AUTOMATIC,
                PrivateDnsCompatibility.read(context).mode)

            assertTrue("Kanaf must switch to Off with verified external grant",
                PrivateDnsToggle.prepare(context))
            assertEquals(PrivateDnsCompatibility.Mode.OFF,
                PrivateDnsCompatibility.read(context).mode)
            assertTrue(PrivateDnsToggle.pending(context))

            assertTrue("Kanaf must restore Auto on user stop",
                PrivateDnsToggle.restoreAuto(context))
            assertEquals(PrivateDnsCompatibility.Mode.AUTOMATIC,
                PrivateDnsCompatibility.read(context).mode)
            assertFalse(PrivateDnsToggle.pending(context))
        } finally {
            // Keep the CI emulator in its original system setting state.
            Settings.Global.putString(
                resolver, "private_dns_mode", original ?: "opportunistic")
        }
    }
}
