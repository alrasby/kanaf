package com.kanaf.alrasby.engine

import org.junit.Assert.*
import org.junit.Test

class NativeScanProtocolTest {
    private val sha = "a".repeat(64)
    private val ready = listOf(
        NativeEngineGate("clamav", true, true, true, "1.4.3", "EICAR-test-v1"),
        NativeEngineGate("yara-x", true, true, true, "0.13.0", "EICAR-test-v1")
    )

    @Test fun fullDatabaseStartupHasABoundedColdStartAllowance() {
        assertEquals(90_000L, NativeScanProtocol.watchdogMs(NativeScanProtocol.REQUEST_FILE, false))
        assertEquals(175_000L, NativeScanProtocol.watchdogMs(NativeScanProtocol.REQUEST_FILE, true))
        assertEquals(90_000L, NativeScanProtocol.watchdogMs(NativeScanProtocol.REQUEST_DEBUG_CRASH, true))
    }

    @Test fun validDetectionsAndNoMatchRoundTrip() {
        val report = NativeScannerBridge.Report(
            AntivirusEngine.Verdict.Detected("Kanaf.EICAR.Test", sha),
            AntivirusEngine.Verdict.NoKnownMatch(sha), ready
        )
        val decoded = NativeScanProtocol.decode(NativeScanProtocol.encode(report))
        assertEquals(report.clamav, decoded.clamav)
        assertEquals(report.yaraX, decoded.yaraX)
        assertTrue(decoded.gates.all { it.ready })
    }

    @Test fun missingOrCorruptResponseNeverMeansClean() {
        val empty = NativeScanProtocol.decode(emptyMap())
        assertTrue(empty.clamav is AntivirusEngine.Verdict.Incomplete)
        assertTrue(empty.yaraX is AntivirusEngine.Verdict.Incomplete)
        val original = NativeScannerBridge.Report(
            AntivirusEngine.Verdict.NoKnownMatch(sha),
            AntivirusEngine.Verdict.NoKnownMatch(sha), ready
        )
        val invalid = NativeScanProtocol.encode(original).toMutableMap()
        invalid["clamav.sha"] = "not-a-sha"
        invalid["yara-x.loaded"] = "0"
        val parsed = NativeScanProtocol.decode(invalid)
        assertTrue(parsed.clamav is AntivirusEngine.Verdict.Incomplete)
        assertTrue(parsed.yaraX is AntivirusEngine.Verdict.Incomplete)
    }

    @Test fun incompleteVerdictSurvivesRoundTrip() {
        val report = NativeScanProtocol.unavailable("scanner-process-disconnected")
        val parsed = NativeScanProtocol.decode(NativeScanProtocol.encode(report))
        assertTrue(parsed.clamav is AntivirusEngine.Verdict.Incomplete)
        assertTrue(parsed.yaraX is AntivirusEngine.Verdict.Incomplete)
        assertFalse(parsed.gates.any { it.ready })
    }

    @Test fun missingReadinessGateCannotReturnDetection() {
        val report = NativeScannerBridge.Report(
            AntivirusEngine.Verdict.Detected("EICAR", sha),
            AntivirusEngine.Verdict.NoKnownMatch(sha),
            emptyList()
        )
        val parsed = NativeScanProtocol.decode(NativeScanProtocol.encode(report))
        assertTrue(parsed.clamav is AntivirusEngine.Verdict.Incomplete)
        assertTrue(parsed.yaraX is AntivirusEngine.Verdict.Incomplete)
    }

    @Test fun invalidRequestReturnsFailClosed() {
        val report = NativeScanProtocol.unavailable("")
        assertTrue(report.clamav is AntivirusEngine.Verdict.Incomplete)
        assertTrue((report.clamav as AntivirusEngine.Verdict.Incomplete).reason.isNotBlank())
    }
}
