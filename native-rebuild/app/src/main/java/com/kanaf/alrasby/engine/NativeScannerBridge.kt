package com.kanaf.alrasby.engine

import android.content.Context
import com.kanaf.alrasby.BuildConfig
import android.content.pm.ApplicationInfo
import android.util.Log
import android.net.Uri
import java.io.File
import java.io.ByteArrayInputStream
import java.io.InputStream
import java.io.ByteArrayOutputStream
import java.security.MessageDigest

/**
 * Bounded native scanning with digest-pinned ESET research rules and authenticated
 * exact-file updates. EICAR fixtures are reserved for engine self-tests.
 * All failures and partial reads are INCOMPLETE, never clean.
 */
object NativeScannerBridge {
    internal const val MB = 1024L * 1024
    internal const val YARA_INPUT_LIMIT = 64L * MB
    internal const val OFFICIAL_CLAM_INPUT_LIMIT = 256L * MB
    internal val inputLimit: Long
        get() = if (OfficialClamDatabase.bundled) OFFICIAL_CLAM_INPUT_LIMIT else YARA_INPUT_LIMIT
    private const val CLAM_RULE_HASH = "f7a0ea8212c9251375ccf756743c34f59732e4edb29ee9cf58e48397c53c93be"
    private const val YARA_RULE_HASH = "6512c037bf11c594476492bd9e1cef968349a79a3a06f50aafa26e4ef3fc0993"
    // Scoped to this process lifetime. Never cache per-file detection verdicts,
    // signature trust, file hashes, or library load failures.
    private val verdictCache = NativeVerdictCache()
    private val passedEngineSelfTest = java.util.concurrent.atomic.AtomicBoolean(false)

    data class Report(
        val clamav: AntivirusEngine.Verdict,
        val yaraX: AntivirusEngine.Verdict,
        val gates: List<NativeEngineGate>
    )

    private external fun clamOfficialScanNative(path: String, database: String, temporary: String): String
    private external fun clamScanNative(path: String, database: String, exactFileOnly: Boolean = false): String
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
    fun scan(context: Context, uri: Uri): Report = scan(context, uri, true)

    internal fun scan(context: Context, uri: Uri, allowOfficial: Boolean): Report =
        NativeScanProcessClient.execute(context, NativeScanProtocol.REQUEST_FILE, uri, allowOfficial)

    /** Built-in harmless EICAR self-test, executed in a separate worker process. */
    fun selfTest(context: Context): Report =
        NativeScanProcessClient.execute(context, NativeScanProtocol.REQUEST_SELF_TEST, null)

    /** Only called by the scanner Service running in :scanner. Never call from the UI process. */
    internal fun scanInWorker(context: Context, uri: Uri, allowOfficial: Boolean): Report =
        scanSource(context, false, allowOfficial) { context.contentResolver.openInputStream(uri) }

    internal fun selfTestInWorker(context: Context): Report =
        scanSource(context, true, true) { ByteArrayInputStream(eicar) }

    private fun verifiedProductionAsset(context: Context, name: String,
                                        expectedSha: String, maxBytes: Int): ByteArray? {
        if (!ProductionNativeRulePolicy.validHash(expectedSha)) return null
        return runCatching {
            context.assets.open(name).use { stream ->
                val out = ByteArrayOutputStream()
                val block = ByteArray(8192)
                while (true) {
                    val n = stream.read(block)
                    if (n < 0) break
                    if (n > maxBytes - out.size()) return null
                    if (n > 0) out.write(block, 0, n)
                }
                out.toByteArray()
            }
        }.getOrNull()?.takeIf {
            ProductionNativeRulePolicy.verified(it, expectedSha, maxBytes)
        }
    }

    private val OFFICIAL_RULE_VERSION = "official-" +
        BuildConfig.KANAF_OFFICIAL_CLAM_DIGESTS.split(',').getOrNull(1).orEmpty().take(12)

    private fun scanOfficial(context: Context, file: File, sha: String): AntivirusEngine.Verdict {
        val database = try {
            OfficialClamDatabase.prepare(context)
        } catch (failure: IllegalStateException) {
            return incomplete(if (failure.message == "clamav-official-device-memory")
                "clamav-official-device-memory" else "clamav-official-assets-unavailable")
        } catch (_: Exception) {
            return incomplete("clamav-official-assets-unavailable")
        }
        return verdict(clamOfficialScanNative(file.absolutePath, database.absolutePath,
            context.cacheDir.absolutePath), sha)
    }

    private fun scanSource(context: Context, selfTestOnly: Boolean, allowOfficial: Boolean,
                           source: () -> InputStream?): Report {
        var clamGate = NativeEngineGate("clamav", false, false, false)
        var yaraGate = NativeEngineGate("yara-x", false, false, false)
        fun report(clam: AntivirusEngine.Verdict, yara: AntivirusEngine.Verdict) =
            Report(clam, yara, listOf(clamGate, yaraGate))

        val libraries = NativeLibraryLoader.probe()
        val bridgeLoaded = runCatching { System.loadLibrary("kanaf_scan"); true }.getOrDefault(false)
        if (!bridgeLoaded) return report(incomplete("jni-bridge-unavailable"), incomplete("jni-bridge-unavailable"))

        var db: File? = null
        var productionDb: File? = null
        var test: File? = null
        var target: File? = null
        try {
            val clamBytes = context.assets.open("kanaf_test.ndb").use { it.readBytes() }
            val yaraBytes = context.assets.open("kanaf_test.yar").use { it.readBytes() }
            val clamRulesOK = digest(clamBytes) == CLAM_RULE_HASH
            val yaraRulesOK = digest(yaraBytes) == YARA_RULE_HASH
            val rulesFile = stagedFile(context, "kanaf-clam-", ".ndb", clamBytes)
            db = rulesFile
            val yaraRules = yaraBytes.toString(Charsets.UTF_8)
            // Positive self-test: the real native engine MUST find the harmless EICAR pattern.
            // Negative self-test prevents a scanner that reports every file as infected.
            val clamOK: Boolean
            val yaraOK: Boolean
            val cached = !selfTestOnly && passedEngineSelfTest.get() &&
                libraries.clamavLoaded && libraries.yaraXLoaded &&
                clamRulesOK && yaraRulesOK
            if (cached) {
                // Reuse only a positive AND negative native EICAR diagnostic
                // already passed in this same scanner process. Every actual
                // user file still goes through BOTH native engines.
                clamOK = true
                yaraOK = true
            } else {
                val testFile = stagedFile(context, "kanaf-eicar-", ".txt", eicar)
                test = testFile
                val benign = stagedFile(context, "kanaf-benign-", ".txt",
                    "kanaf-scan-control".toByteArray())
                try {
                    val clamPositive = if (libraries.clamavLoaded && clamRulesOK)
                    clamScanNative(testFile.absolutePath, rulesFile.absolutePath) else "NOT_RUN"
                val clamPositiveExpected = NativeSelfTestPolicy.expected("clamav", clamPositive)
                val clamNegative = if (clamPositiveExpected)
                    clamScanNative(benign.absolutePath, rulesFile.absolutePath) else "NOT_RUN"
                // Prove the real SHA-256 wildcard .hsb loader as well as the
                // NDB content matcher with non-executable controls.
                val hashControl = stagedFile(context, "kanaf-clam-hash-control-", ".hsb",
                    NativeHashRules.clam(mapOf(digest(eicar) to "Kanaf.EICAR.Test")))
                val hashPositive: String
                val hashNegative: String
                try {
                    hashPositive = if (libraries.clamavLoaded) clamScanNative(testFile.absolutePath, hashControl.absolutePath) else "NOT_RUN"
                    hashNegative = if (libraries.clamavLoaded) clamScanNative(benign.absolutePath, hashControl.absolutePath) else "NOT_RUN"
                } finally { hashControl.delete() }
                clamOK = clamPositiveExpected && clamNegative == "NO_MATCH" &&
                    NativeSelfTestPolicy.expected("clamav", hashPositive) && hashNegative == "NO_MATCH"
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
                if (clamOK && yaraOK && clamRulesOK && yaraRulesOK &&
                    libraries.clamavLoaded && libraries.yaraXLoaded) {
                    passedEngineSelfTest.set(true)
                }
            }
            // Debug builds use EICAR fixtures for diagnostics. In production
            // regular user files must NEVER be checked only against test rules.
            // Independent real-rule assets must be pinned in BuildConfig and
            // verified before a native scan can return NoKnownMatch.
            val production = !selfTestOnly
            val realClam = if (production) verifiedProductionAsset(context,
                "production_clamav.hsb", BuildConfig.KANAF_NATIVE_CLAM_RULE_SHA256,
                ProductionNativeRulePolicy.MAX_CLAM_BYTES) else null
            val realYara = if (production) verifiedProductionAsset(context,
                "production_yara.yar", BuildConfig.KANAF_NATIVE_YARA_RULE_SHA256,
                ProductionNativeRulePolicy.MAX_YARA_BYTES) else null
            // The signed feed updates exact-file rules in BOTH native engines.
            // Retain the independently pinned content rules, but replace old
            // exact hashes so a later signed feed can revoke an obsolete IOC.
            val trustedRows = if (production && realClam != null && realYara != null &&
                BuildConfig.KANAF_SIGNATURE_MIN_VERSION > 0L)
                SignatureRepository(context).loadSnapshot()
                    .takeIf { it.version > 1L }?.rows else null
            val activeClamBytes = (if (trustedRows != null) NativeHashRules.clam(trustedRows) else realClam)?.let { rules ->
                // Standard harmless diagnostic remains identifiable as a TEST
                // alongside real rules; it is never counted as malware evidence.
                rules + (digest(eicar) + ":68:Kanaf.EICAR.Test:73\n").toByteArray(Charsets.US_ASCII)
            }
            if (activeClamBytes != null) {
                productionDb = stagedFile(context, "kanaf-clam-prod-", ".hsb", activeClamBytes)
            }
            val activeClam = if (production) productionDb else rulesFile
            val activeYara = if (production) realYara?.toString(Charsets.UTF_8)?.let { pinned ->
                if (trustedRows != null) {
                    check(pinned.contains("// KANAF_EXACT_HASH_RULES"))
                    pinned.substringBefore("// KANAF_EXACT_HASH_RULES") + NativeHashRules.yara(trustedRows)
                } else pinned
            }?.plus("\nrule Kanaf_EICAR_Test { condition: filesize == 68 and hash.sha256(0, filesize) == \"" +
                digest(eicar) + "\" }\n") else yaraRules
            clamGate = NativeEngineGate("clamav", libraries.clamavLoaded,
                clamRulesOK && (!production || realClam != null), clamOK,
                engineVersion = "1.4.6",
                rulesVersion = if (production) "research-native-v2" else "EICAR-test-v1")
            yaraGate = NativeEngineGate("yara-x", libraries.yaraXLoaded,
                yaraRulesOK && (!production || realYara != null), yaraOK,
                engineVersion = "0.13.0",
                rulesVersion = if (production) "research-native-v2" else "EICAR-test-v1")

            val selected = File.createTempFile("kanaf-scan-", ".bin", context.cacheDir)
            target = selected
            var copiedBytes = -1L
            val sha256 = try {
                val input = source()
                    ?: return report(incomplete("file-unavailable"), incomplete("file-unavailable"))
                input.use { sourceStream ->
                    selected.outputStream().use { output ->
                        when (val copied = BoundedStreamCopier(maxBytes = inputLimit)
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
                !StagedFileIntegrity.verify(selected, sha256, copiedBytes, inputLimit)) {
                return report(incomplete("staged-file-integrity-failed"),
                    incomplete("staged-file-integrity-failed"))
            }
            // A cached mobile verdict does not record whether the full engine
            // actually ran. Full builds reuse the compiled engine, not that verdict.
            val cacheKey = if (production && !OfficialClamDatabase.bundled &&
                clamGate.ready && yaraGate.ready &&
                activeClamBytes != null && activeYara != null)
                NativeVerdictCache.Key(
                    sha256, digest(activeClamBytes),
                    digest(activeYara.toByteArray())
                ) else null
            val cachedVerdicts = cacheKey?.let(verdictCache::get)
            val localClam = cachedVerdicts?.first ?: if (clamGate.ready && activeClam != null) verdict(
                clamScanNative(selected.absolutePath, activeClam.absolutePath,
                    exactFileOnly = production && OfficialClamDatabase.bundled), sha256
            ) else incomplete(if (production && realClam == null)
                "production-clamav-rules-unavailable"
            else clamGate.unavailableReason() ?: "clamav-not-ready")
            val clamVerdict = when {
                !OfficialClamDatabase.bundled -> localClam
                selfTestOnly && localClam is AntivirusEngine.Verdict.Detected -> {
                    clamGate = clamGate.copy(rulesVersion = OFFICIAL_RULE_VERSION)
                    scanOfficial(context, selected, sha256).let { official ->
                        if (official is AntivirusEngine.Verdict.Detected &&
                            ThreatFamily.classify(official.threatName) != ThreatFamily.Kind.TEST_SAMPLE) {
                            incomplete("clamav-official-self-test-unexpected-match")
                        } else official
                    }
                }
                selfTestOnly || localClam is AntivirusEngine.Verdict.Detected -> localClam
                !allowOfficial -> incomplete("clamav-official-skipped-after-worker-exit")
                else -> scanOfficial(context, selected, sha256).let { official ->
                    val reason = (official as? AntivirusEngine.Verdict.Incomplete)?.reason.orEmpty()
                    clamGate = clamGate.copy(rulesVersion = OFFICIAL_RULE_VERSION,
                        rulesVerified = !reason.removePrefix("INCOMPLETE:").startsWith("clamav-official-"))
                    // A missing supplemental engine still limits a negative result.
                    if (official is AntivirusEngine.Verdict.NoKnownMatch) localClam else official
                }
            }
            val yaraVerdict = if (copiedBytes > YARA_INPUT_LIMIT) incomplete("yara-input-size-limit")
            else cachedVerdicts?.second ?: if (yaraGate.ready && activeYara != null) verdict(
                yaraScanNative(selected.absolutePath, activeYara), sha256
            ) else incomplete(if (production && realYara == null)
                "production-yara-rules-unavailable"
            else yaraGate.unavailableReason() ?: "yara-not-ready")
            if (!StagedFileIntegrity.verify(selected, sha256, copiedBytes, inputLimit)) {
                return report(incomplete("staged-file-changed-during-scan"),
                    incomplete("staged-file-changed-during-scan"))
            }
            cacheKey?.let { verdictCache.put(it, clamVerdict, yaraVerdict) }
            return report(clamVerdict, yaraVerdict)
        } catch (_: Exception) {
            return report(incomplete("native-initialization-failed"), incomplete("native-initialization-failed"))
        } catch (_: UnsatisfiedLinkError) {
            return report(incomplete("native-symbol-unavailable"), incomplete("native-symbol-unavailable"))
        } finally {
            db?.delete()
            productionDb?.delete()
            test?.delete()
            target?.delete()
        }
    }
}
