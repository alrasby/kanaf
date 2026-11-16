package com.kanaf.alrasby

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.kanaf.alrasby.engine.KanafUrlAi
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith

/** Verifies the exact model+public-key bytes packaged into an Android APK. */
@RunWith(AndroidJUnit4::class)
class KanafUrlAiAndroidTest {
    @Test fun packagedPilotModelLoadsAndScoresWithoutNetworking() {
        val ctx = InstrumentationRegistry.getInstrumentation().targetContext
        val model = KanafUrlAi.load(ctx)
        if (BuildConfig.KANAF_URL_MODEL_PUBLIC_KEY_BASE64.isBlank()) {
            assertNull(model)
            return
        }
        assertNotNull("Signed model must load from packaged APK", model)
        assertEquals("phiusiiil-url-pilot-1", model!!.version)
        val first = model.evaluate("https://example.com/about")
        val second = model.evaluate("http://192.0.2.44/confirm-password?session=123")
        assertNotNull(first)
        assertNotNull(second)
        assertTrue(first!! in 0f..1f && second!! in 0f..1f)
        assertNotEquals(first, second)
        assertNull(model.evaluate("mailto:someone@example.org"))
    }
}
