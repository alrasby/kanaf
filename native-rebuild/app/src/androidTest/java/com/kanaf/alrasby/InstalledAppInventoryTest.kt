package com.kanaf.alrasby

import android.provider.Settings
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.kanaf.alrasby.engine.InstalledAppInventory
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith

/** Verify Android scoped package visibility without QUERY_ALL_PACKAGES. */
@RunWith(AndroidJUnit4::class)
class InstalledAppInventoryTest {
    @Test fun includesOwnLaunchableAppAndOpensItsSystemSettings() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val inventory = InstalledAppInventory()
        val apps = inventory.load(context)
        assertTrue("This app has a launcher activity", apps.any {
            it.packageName == context.packageName
        })
        assertEquals(apps.map { it.packageName }.toSet().size, apps.size)
        val intent = inventory.settingsIntent(context.packageName)
        assertEquals(Settings.ACTION_APPLICATION_DETAILS_SETTINGS, intent.action)
        assertEquals("package:${context.packageName}", intent.data.toString())
    }

    @Test fun malformedPackageNeverBecomesAndroidSettingsIntent() {
        assertThrows(IllegalArgumentException::class.java) {
            InstalledAppInventory().settingsIntent("bad/../name")
        }
    }
}
