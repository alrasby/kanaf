package com.kanaf.alrasby

import android.content.pm.PackageManager
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.kanaf.alrasby.engine.PrivateDnsCompatibility
import com.kanaf.alrasby.engine.PrivateDnsToggle
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class PrivateDnsToggleAndroidTest {
    @Test fun ordinaryConsumerAppHasNoWriteSecureSettingsPrivilege() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        assertEquals(PackageManager.PERMISSION_DENIED, context.checkSelfPermission(
            "android.permission.WRITE_SECURE_SETTINGS"))
        assertFalse(PrivateDnsToggle.granted(context))
        assertFalse(PrivateDnsToggle.pending(context))
        assertEquals(PrivateDnsToggle.Decision.READY,
            PrivateDnsToggle.decision(PrivateDnsCompatibility.interpret(
                "opportunistic", null, null, encryptedDnsActive = true)))
        assertEquals(PrivateDnsToggle.Decision.MANUAL_REQUIRED,
            PrivateDnsToggle.decision(PrivateDnsCompatibility.interpret(
                "hostname", null, "family.adguard-dns.com")))
    }
}
