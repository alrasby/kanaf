package com.kanaf.alrasby.engine

import org.junit.Assert.*
import org.junit.Test

class ScanEvidenceTextTest {
    private val sha = "a".repeat(64)
    private val otherSha = "b".repeat(64)
    @Test fun mismatchingHashesKeepRawDetectionsUnconfirmed() {
        val decision = EngineConsensus.evaluate(
            listOf(EngineConsensus.Report("clamav", AntivirusEngine.Verdict.Detected("KnownRule", sha)),
                EngineConsensus.Report("yara-x", AntivirusEngine.Verdict.NoKnownMatch(otherSha))),
            setOf("clamav", "yara-x"))
        assertTrue(ScanEvidenceText.hasConflict(decision))
        val native = ScanEvidenceText.nativeLabel(
            "ClamAV", AntivirusEngine.Verdict.Detected("KnownRule", sha), true)
        assertTrue(native.contains("KnownRule"))
        assertTrue(native.contains("لا يمكن تأكيد"))
        val local = ScanEvidenceText.hashLabel(
            AntivirusEngine.Verdict.Detected("KnownRule", sha), 1, true)
        assertTrue(local.contains("لا يمكن تأكيد"))
        assertFalse(local.contains("تطابق توقيع تهديد:"))
    }
    @Test fun negativeResultsAreNotClaimsOfSafetyDuringConflict() {
        val local = ScanEvidenceText.hashLabel(
            AntivirusEngine.Verdict.NoKnownMatch(sha), 2, true)
        val native = ScanEvidenceText.nativeLabel(
            "YARA-X", AntivirusEngine.Verdict.NoKnownMatch(sha), true)
        assertTrue(local.contains("ليست نتيجة سلامة"))
        assertTrue(native.contains("غير معتمدة"))
    }
    @Test fun backdoorCategoryRequiresActualSignatureMatch() {
        val found = AntivirusEngine.Verdict.Detected("Backdoor.Android.Agent", sha)
        assertTrue(ScanEvidenceText.hashLabel(found, 1, false).contains("Backdoor"))
        assertTrue(ScanEvidenceText.hashLabel(found, 1, true).contains("باب خلفي"))
        assertTrue(ScanEvidenceText.nativeLabel("YARA-X", found, false, false)
            .contains("Signature match"))
        val sample = AntivirusEngine.Verdict.Detected("Kanaf_EICAR_Test", sha)
        assertTrue(ScanEvidenceText.nativeLabel("YARA-X", sample, false, false)
            .contains("Harmless EICAR"))
    }

    @Test fun nonConflictingAndIncompleteResultsKeepOriginalWording() {
        val decision = EngineConsensus.evaluate(
            listOf(EngineConsensus.Report("clamav", AntivirusEngine.Verdict.NoKnownMatch(sha))),
            setOf("clamav"))
        assertFalse(ScanEvidenceText.hasConflict(decision))
        assertTrue(ScanEvidenceText.nativeLabel(
            "ClamAV", AntivirusEngine.Verdict.NoKnownMatch(sha), false).contains("لا تطابق"))
        assertTrue(ScanEvidenceText.hashLabel(
            AntivirusEngine.Verdict.Incomplete("timeout"), 0, true).contains("الفحص غير مكتمل"))
    }
}
