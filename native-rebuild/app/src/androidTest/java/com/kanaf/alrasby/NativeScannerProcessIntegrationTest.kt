package com.kanaf.alrasby

import android.content.ComponentName
import android.content.pm.PackageManager
import android.net.Uri
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.kanaf.alrasby.engine.AntivirusEngine
import com.kanaf.alrasby.engine.NativeScannerBridge
import com.kanaf.alrasby.engine.NativeScannerService
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/** On-device smoke coverage of the bound scanner process and fail-closed IPC. */
@RunWith(AndroidJUnit4::class)
class NativeScannerProcessIntegrationTest {
    private val appContext get() = InstrumentationRegistry.getInstrumentation().targetContext

    @Test fun scannerServiceIsPrivateAndRunsInAnotherProcess() {
        val context = appContext
        val info = context.packageManager.getServiceInfo(
            ComponentName(context, NativeScannerService::class.java), 0
        )
        assertFalse("Scanner service may not be exported", info.exported)
        assertEquals("${context.packageName}:scanner", info.processName)
    }

    @Test fun selfTestUsesWorkerIpcWithoutClaimingSafetyOnMissingEngines() {
        val report = NativeScannerBridge.selfTest(appContext)
        assertEquals(2, report.gates.size)
        assertFalse("EICAR self-test must never be reported as clean",
            report.clamav is AntivirusEngine.Verdict.NoKnownMatch)
        assertFalse("EICAR self-test must never be reported as clean",
            report.yaraX is AntivirusEngine.Verdict.NoKnownMatch)
        assertTrue(
            report.clamav is AntivirusEngine.Verdict.Detected ||
                report.clamav is AntivirusEngine.Verdict.Incomplete
        )
        assertTrue(
            report.yaraX is AntivirusEngine.Verdict.Detected ||
                report.yaraX is AntivirusEngine.Verdict.Incomplete
        )
    }

    @Test fun missingContentProviderDoesNotProduceCleanVerdict() {
        val report = NativeScannerBridge.scan(
            appContext, Uri.parse("content://com.kanaf.nonexistent-provider.invalid/missing")
        )
        assertTrue(report.clamav is AntivirusEngine.Verdict.Incomplete)
        assertTrue(report.yaraX is AntivirusEngine.Verdict.Incomplete)
    }
}
