package com.kanaf.alrasby

import android.content.ComponentName
import android.content.pm.PackageManager
import android.net.Uri
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.kanaf.alrasby.engine.AntivirusEngine
import com.kanaf.alrasby.engine.NativeScannerBridge
import com.kanaf.alrasby.engine.NativeScannerService
import com.kanaf.alrasby.engine.NativeScanProcessClient
import com.kanaf.alrasby.engine.NativeScanProtocol
import com.kanaf.alrasby.engine.DeviceNativeScanRecovery
import java.io.File
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

    @Test fun workerDeathFailsClosedAndNextScanRecovers() {
        // This action is only accepted by the private :scanner service in a debuggable app.
        val crashed = NativeScanProcessClient.execute(
            appContext, NativeScanProtocol.REQUEST_DEBUG_CRASH, null
        )
        assertTrue("Worker death must not return a clean ClamAV verdict",
            crashed.clamav is AntivirusEngine.Verdict.Incomplete)
        assertTrue("Worker death must not return a clean YARA-X verdict",
            crashed.yaraX is AntivirusEngine.Verdict.Incomplete)
        val reason = (crashed.clamav as AntivirusEngine.Verdict.Incomplete).reason
        assertTrue("Must observe worker death, not silently time out: $reason",
            reason == "scanner-process-disconnected" || reason == "scanner-binding-died")

        // A new bind must be able to start a fresh :scanner process.
        val next = NativeScannerBridge.selfTest(appContext)
        assertEquals(2, next.gates.size)
        assertFalse(next.clamav is AntivirusEngine.Verdict.NoKnownMatch)
        assertFalse(next.yaraX is AntivirusEngine.Verdict.NoKnownMatch)
    }

    @Test fun missingContentProviderDoesNotProduceCleanVerdict() {
        val report = NativeScannerBridge.scan(
            appContext, Uri.parse("content://com.kanaf.nonexistent-provider.invalid/missing")
        )
        assertTrue(report.clamav is AntivirusEngine.Verdict.Incomplete)
        assertTrue(report.yaraX is AntivirusEngine.Verdict.Incomplete)
    }

    @Test fun yaraStageDeathRetriesWithOfficialClamavAndContinuesClamavOnly() {
        val recovery = DeviceNativeScanRecovery(officialAvailable = true)
        val file = File.createTempFile("engine-recovery-control-", ".txt", appContext.cacheDir)
        try {
            file.writeText("benign control for scanner process recovery")
            val uri = Uri.fromFile(file)
            val requests = mutableListOf<Pair<Boolean, Boolean>>()
            val stages = mutableListOf<String>()
            fun scan() = recovery.scan(stopped = { false }, observe = { report ->
                report.interruptedStage?.let(stages::add)
            }) { allowOfficial, allowYara ->
                requests.add(allowOfficial to allowYara)
                NativeScanProcessClient.execute(appContext, NativeScanProtocol.REQUEST_FILE, uri,
                    allowOfficial, allowYara, debugStopAtYara = allowYara)
            }

            val retried = scan()
            val next = scan()
            assertEquals(listOf("YARA_X"), stages)
            assertEquals(listOf(true to true, true to false, true to false), requests)
            assertEquals(1, recovery.failures)
            for (result in listOf(retried, next)) {
                assertTrue("ClamAV must finish after the YARA-X worker exit: $result",
                    result.clamav is AntivirusEngine.Verdict.NoKnownMatch)
                assertTrue(result.gates.single { it.engineId == "clamav" }.rulesVersion?.startsWith("official-") == true)
                assertEquals(AntivirusEngine.Verdict.Incomplete("yara-paused-after-worker-failure"), result.yaraX)
                assertFalse(result.gates.single { it.engineId == "yara-x" }.libraryLoaded)
            }
        } finally {
            file.delete()
        }
    }
}
