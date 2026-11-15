package com.kanaf.alrasby.engine

import android.content.Context
import android.content.pm.ApplicationInfo
import android.util.Log
import android.net.Uri
import java.io.File
import java.io.ByteArrayInputStream
import java.io.InputStream
import java.security.MessageDigest

/**
 * Experimental native scanning path. The bundled rules ONLY recognize the harmless EICAR
 * test string. This is not a production antivirus database or whole-device protection.
 * All failures and partial reads are INCOMPLETE, never clean.
 */
object NativeScannerBridge {
    private const val MAX_FILE_BYTES = 16L * 1024 * 1024
    private const val CLAM_RULE_HASH = "f7a0ea8212c9251375ccf756743c34f59732e4edb29ee9cf58e48397c53c93be"
    private const val YARA_RULE_HASH = "6512c037bf11c594476492bd9e1cef968349a79a3a06f50aafa26e4ef3fc0993"

    data class Report(
        val clamav: AntivirusEngine.Verdict,
        val yaraX: AntivirusEngine.Verdict,
        val gates: List<NativeEngineGate>
    )

    private external fun clamScanNative(path: String, database: String): String
    // Only a debug-only comparison on the generated EICAR fixture; never a verdict.
    private external fun clamDefaultMatcherDiagnosticNative(path: String, database: String): String
    private external fun yaraScanNative(path: String, rules: String): String

    // These are the official non-executable EICAR test bytes, used only for an engine self-test.
    private val eicar = (
        "X5O!P%@AP[4\\PZX54(P^)7CC)7}" + 36.toChar() +
            "EICAR-STANDARD-ANTIVIRUS-TEST-FILE!" + 36.toChar() + "H+H*"
    ).toByteArray(Charsets.US_ASCII)

    internal fun eicarReferenceForTests(): ByteArray = eicar.copyOf()

    private fun digest(bytes: ByteArray): String =
        MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") {
            "%02x".format(it.toInt() and 0xff)
        }

    private fun incomplete(reason: String) = AntivirusEngine.Verdict.Incomplete(reason)

    internal fun decodeForTests(raw: String, sha256: String): AntivirusEngine.Verdict = verdict(raw, sha256)

    private fun verdict(raw: String, sha256: String): AntivirusEngine.Verdict = when {
        raw.startsWith("DETECTED:") && raw.length > 9 ->
            AntivirusEngine.Verdict.Detected(raw.substringAfter(':').take(128), sha256)
        raw == "NO_MATCH" -> AntivirusEngine.Verdict.NoKnownMatch(sha256)
        else -> incomplete(raw.take(120))
    }

    private fun stagedFile(context: Context, prefix: String, suffix: String, bytes: ByteArray): File =
        File.createTempFile(prefix, suffix, context.cacheDir).also {
            it.outputStream().use { output -> output.write(bytes) }
        }

    /**
     * Must be called on Dispatchers.IO, after the user selects one SAF file.
     * No file is deleted or modified at its original location.
     */
    fun scan(context: Context, uri: Uri): Report =
        NativeScanProcessClient.execute(context, NativeScanProtocol.REQUEST_FILE, uri)

    /** Built-in harmless EICAR self-test, executed in a separate worker process. */
    fun selfTest(context: Context): Report =
        NativeScanProcessClient.execute(context, NativeScanProtocol.REQUEST_SELF_TEST, null)

    /** Only called by the scanner Service running in :scanner. Never call from the UI process. */
    internal fun scanInWorker(context: Context, uri: Uri): Report =
        scanSource(context) { context.contentResolver.openInputStream(uri) }

    internal fun selfTestInWorker(context: Context): Report =
        scanSource(context) { ByteArrayInputStream(eicar) }

    private fun scanSource(context: Context, source: () -> InputStream?): Report {
        var clamGate = NativeEngineGate("clamav", false, false, false)
        var yaraGate = NativeEngineGate("yara-x", false, false, false)
        fun report(clam: AntivirusEngine.Verdict, yara: AntivirusEngine.Verdict) =
            Report(clam, yara, listOf(clamGate, yaraGate))

        val libraries = NativeLibraryLoader.probe()
        val bridgeLoaded = runCatching { System.loadLibrary("kanaf_scan"); true }.getOrDefault(false)
        if (!bridgeLoaded) return report(incomplete("jni-bridge-unavailable"), incomplete("jni-bridge-unavailable"))

        var db: File? = null
        var test: File? = null
        var target: File? = null
        try {
            val clamBytes = context.assets.open("kanaf_test.ndb").use { it.readBytes() }
            val yaraBytes = context.assets.open("kanaf_test.yar").use { it.readBytes() }
            val clamRulesOK = digest(clamBytes) == CLAM_RULE_HASH
            val yaraRulesOK = digest(yaraBytes) == YARA_RULE_HASH
            val rulesFile = stagedFile(context, "kanaf-clam-", ".ndb", clamBytes)
            db = rulesFile
            val testFile = stagedFile(context, "kanaf-eicar-", ".txt", eicar)
            test = testFile
            val yaraRules = yaraBytes.toString(Charsets.UTF_8)
            // Positive self-test: the real native engine MUST find the harmless EICAR pattern.
            // Negative self-test prevents a scanner that reports every file as infected.
            val benign = stagedFile(context, "kanaf-benign-", ".txt", "kanaf-scan-control".toByteArray())
            val clamOK: Boolean
            val yaraOK: Boolean
            try {
                val clamPositive = if (libraries.clamavLoaded && clamRulesOK)
                    clamScanNative(testFile.absolutePath, rulesFile.absolutePath) else "NOT_RUN"
                val clamPositiveExpected = NativeSelfTestPolicy.expected("clamav", clamPositive)
                val clamNegative = if (clamPositiveExpected)
                    clamScanNative(benign.absolutePath, rulesFile.absolutePath) else "NOT_RUN"
                clamOK = clamPositiveExpected && clamNegative == "NO_MATCH"
                val yaraPositive = if (libraries.yaraXLoaded && yaraRulesOK)
                    yaraScanNative(testFile.absolutePath, yaraRules) else "NOT_RUN"
                val yaraPositiveExpected = NativeSelfTestPolicy.expected("yara-x", yaraPositive)
                val yaraNegative = if (yaraPositiveExpected)
                    yaraScanNative(benign.absolutePath, yaraRules) else "NOT_RUN"
                yaraOK = yaraPositiveExpected && yaraNegative == "NO_MATCH"
                // Only harmless built-in fixtures; never log data from selected files.
                if (context.applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE != 0) {
                    Log.i("KanafNativeSelfTest", "ClamAV EICAR=" + clamPositive.take(100) +
                        ", benign=" + clamNegative.take(100) +
                        "; YARA-X EICAR=" + yaraPositive.take(100) +
                        ", benign=" + yaraNegative.take(100))
                    // Diagnostic only. A hash-based match MUST NEVER stand in
                    // for a failing NDB content matcher in the readiness gate.
                    // This distinguishes "ClamAV cannot match any signatures"
                    // from "Android ARM64 AC/BM matching is broken".
                    if (libraries.clamavLoaded && clamRulesOK && !clamPositiveExpected) {
                        val defaultResult = runCatching {
                            clamDefaultMatcherDiagnosticNative(
                                testFile.absolutePath, rulesFile.absolutePath
                            )
                        }.getOrDefault("INCOMPLETE:diagnostic-unavailable")
                        Log.i("KanafNativeSelfTest",
                            "ClamAV default matcher EICAR=" + defaultResult.take(100) +
                                " (diagnostic only; readiness unchanged)")
                        val hashDb = stagedFile(context, "kanaf-hashdiag-", ".hdb",
                            ("44d88612fea8a8f36de82e1278abb02f:68:" +
                                "Kanaf.EICAR.MD5.Diagnostic\\n")
                                .replace("\\n", "\n").toByteArray(Charsets.US_ASCII))
                        val padded = stagedFile(context, "kanaf-paddeddiag-", ".bin",
                            eicar + ByteArray(4096) { 'x'.code.toByte() })
                        try {
                            val md5Outcome = clamScanNative(testFile.absolutePath, hashDb.absolutePath)
                            val paddedOutcome = clamScanNative(padded.absolutePath, rulesFile.absolutePath)
                            Log.i("KanafNativeSelfTest",
                                "ClamAV diagnostic hash=" + md5Outcome.take(100) +
                                    " padded-ndb=" + paddedOutcome.take(100) +
                                    " (diagnostic only, never changes readiness)")
                        } finally {
                            hashDb.delete()
                            padded.delete()
                        }
                    }
                }
            } finally {
                benign.delete()
            }
            clamGate = NativeEngineGate("clamav", libraries.clamavLoaded, clamRulesOK, clamOK,
                engineVersion = "1.4.6", rulesVersion = "EICAR-test-v1")
            yaraGate = NativeEngineGate("yara-x", libraries.yaraXLoaded, yaraRulesOK, yaraOK,
                engineVersion = "0.13.0", rulesVersion = "EICAR-test-v1")

            val selected = File.createTempFile("kanaf-scan-", ".bin", context.cacheDir)
            target = selected
            var copiedBytes = -1L
            val sha256 = try {
                val input = source()
                    ?: return report(incomplete("file-unavailable"), incomplete("file-unavailable"))
                input.use { sourceStream ->
                    selected.outputStream().use { output ->
                        when (val copied = BoundedStreamCopier(maxBytes = MAX_FILE_BYTES)
                            .copy(sourceStream, output)) {
                            is BoundedStreamCopier.Result.Complete -> {
                                copiedBytes = copied.bytesCopied
                                copied.sha256
                            }
                            is BoundedStreamCopier.Result.Incomplete ->
                                return report(incomplete("copy-" + copied.reason), incomplete("copy-" + copied.reason))
                        }
                    }
                }
            } catch (_: Exception) {
                return report(incomplete("file-unreadable"), incomplete("file-unreadable"))
            }
            // The source can change between reads. Seal the private snapshot and
            // verify that both engines receive the same bytes we hashed.
            if (!StagedFileIntegrity.seal(selected) ||
                !StagedFileIntegrity.verify(selected, sha256, copiedBytes)) {
                return report(incomplete("staged-file-integrity-failed"),
                    incomplete("staged-file-integrity-failed"))
            }
            val clamVerdict = if (clamGate.ready) verdict(
                clamScanNative(selected.absolutePath, rulesFile.absolutePath), sha256
            ) else incomplete(clamGate.unavailableReason() ?: "clamav-not-ready")
            val yaraVerdict = if (yaraGate.ready) verdict(
                yaraScanNative(selected.absolutePath, yaraRules), sha256
            ) else incomplete(yaraGate.unavailableReason() ?: "yara-not-ready")
            if (!StagedFileIntegrity.verify(selected, sha256, copiedBytes)) {
                return report(incomplete("staged-file-changed-during-scan"),
                    incomplete("staged-file-changed-during-scan"))
            }
            return report(clamVerdict, yaraVerdict)
        } catch (_: Exception) {
            return report(incomplete("native-initialization-failed"), incomplete("native-initialization-failed"))
        } catch (_: UnsatisfiedLinkError) {
            return report(incomplete("native-symbol-unavailable"), incomplete("native-symbol-unavailable"))
        } finally {
            db?.delete()
            test?.delete()
            target?.delete()
        }
    }
}
