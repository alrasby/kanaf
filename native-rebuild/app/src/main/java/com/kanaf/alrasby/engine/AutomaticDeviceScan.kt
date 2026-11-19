package com.kanaf.alrasby.engine

import android.content.Context
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.os.Environment
import android.os.SystemClock
import java.io.File
import java.nio.file.Files
import java.util.ArrayDeque

/**
 * One-tap, user-initiated inventory scan: installed package APKs and accessible
 * primary shared-storage documents. No picker, uploads, quarantine or deletion.
 *
 * Android private application data and protected OS areas remain out of scope
 * even with All files access. Results NEVER claim full malware-free status.
 */
class AutomaticDeviceScan {
    data class Finding(val source: String, val label: String, val isSignature: Boolean)
    data class Progress(val attempted: Int, val applications: Int, val phase: String)
    data class Report(
        val installedApps: Int, val appApksAttempted: Int,
        val sharedFilesAttempted: Int, val hashed: Int, val nativeChecked: Int,
        val matches: Int, val incomplete: Int, val structuralWarnings: Int,
        val truncated: Boolean, val sharedStorageGranted: Boolean,
        val signaturesReady: Boolean, val findings: List<Finding>,
        val storedApksAttempted: Int = 0,
        val nativeInstalledAttempts: Int = 0,
        val nativeSharedAttempts: Int = 0,
        val incompleteReasons: Map<String, Int> = emptyMap()
    )

    companion object {
        private const val MAX_APK_FILES = 1400
        private const val MAX_SHARED_FILES = 4000
        private const val MAX_DIRECTORIES = 1600
        private const val MAX_DEPTH = 12
        private const val MAX_RUNTIME_MS = 8 * 60_000L
        private const val MAX_HASH_BYTES = 256L * 1024 * 1024
        private const val MAX_NATIVE_BYTES = 64L * 1024 * 1024
        private const val MAX_NATIVE_CHECKS = 100

        fun sharedStorageGranted(): Boolean = if (Build.VERSION.SDK_INT >= 30) {
            Environment.isExternalStorageManager()
        } else true // Android <= 10: request READ_EXTERNAL_STORAGE in the UI.
    }

    /** Injectable limits for emulator QA; never exceed production ceilings. */
    data class Limits(
        val apkFiles: Int = MAX_APK_FILES,
        val sharedFiles: Int = MAX_SHARED_FILES,
        val nativeChecks: Int = MAX_NATIVE_CHECKS,
        val durationMs: Long = MAX_RUNTIME_MS,
        val hashBytes: Long = MAX_HASH_BYTES
    ) {
        init {
            require(apkFiles in 1..MAX_APK_FILES)
            require(sharedFiles in 1..MAX_SHARED_FILES)
            require(nativeChecks in 0..MAX_NATIVE_CHECKS)
            require(durationMs in 1..MAX_RUNTIME_MS)
            require(hashBytes in 1..MAX_HASH_BYTES)
        }
    }

    fun run(
        context: Context,
        includeSharedStorage: Boolean,
        cancelled: () -> Boolean = { false },
        progress: (Progress) -> Unit = {},
        limits: Limits = Limits()
    ): Report {
        val start = SystemClock.elapsedRealtime()
        fun stopped() = cancelled() || Thread.currentThread().isInterrupted ||
            SystemClock.elapsedRealtime() - start > limits.durationMs

        val signatures = runCatching { SignatureRepository(context).load() }.getOrNull()
        val canReadShared = includeSharedStorage && sharedStorageGranted()
        val allocation = NativeScanAllocation(limits.nativeChecks, canReadShared)
        // Reuse stateless hashing objects, rather than allocating a scanner
        // and its configuration thousands of times per one-tap scan.
        val hashEngine = HashSignatureEngine(signatures,
            StreamScanner(maxBytes = limits.hashBytes,
                maxDurationNanos = 25_000_000_000L,
                signatures = signatures ?: emptyMap()))
        val packageManager = context.packageManager
        val applications = try {
            @Suppress("DEPRECATION")
            if (Build.VERSION.SDK_INT >= 33) {
                packageManager.getInstalledApplications(
                    PackageManager.ApplicationInfoFlags.of(0L))
            } else packageManager.getInstalledApplications(0)
        } catch (_: Exception) { emptyList() }
        val packages = applications.sortedBy { it.packageName }
        var apkAttempted = 0
        var sharedAttempted = 0
        var hashed = 0
        var nativeChecked = 0
        var storedApksAttempted = 0
        var matched = 0
        var incomplete = 0
        var structuralWarnings = 0
        var truncated = false
        val findings = ArrayList<Finding>(16)
        val incompleteReasons = linkedMapOf<String, Int>()
        fun reason(text: String) { incompleteReasons[text.take(120)] = (incompleteReasons[text.take(120)] ?: 0) + 1 }
        fun reasons(reports: List<EngineConsensus.Report>) = reports.forEach {
            (it.verdict as? AntivirusEngine.Verdict.Incomplete)?.let { verdict -> reason(verdict.reason) }
        }
        val processed = HashSet<String>()
        var notifiedAt = 0

        fun notifyProgress(phase: String) {
            val attempted = apkAttempted + sharedAttempted
            if (attempted == 0 || attempted - notifiedAt >= 12) {
                notifiedAt = attempted
                progress(Progress(attempted, packages.size, phase))
            }
        }

        fun record(file: File, display: String, installedApp: Boolean) {
            val apk = installedApp || file.name.endsWith(".apk", ignoreCase = true)
            val archived = apk || file.name.endsWith(".zip", ignoreCase = true)
            if (stopped()) { truncated = true; return }
            if (!file.isFile || !file.canRead() || file.length() <= 0 ||
                file.length() > limits.hashBytes) {
                incomplete++
                reason("file-unreadable-empty-or-size-limit")
                return
            }
            // All three engines must describe the same immutable file snapshot.
            // The SHA-256 adapter reads first; native JNI copies a second time.
            // A changed input invalidates an apparent detection rather than
            // silently treating two different versions as one malicious file.
            val hashVerdict = hashEngine.scan({ file.inputStream() }, ::stopped)
            if (hashVerdict is AntivirusEngine.Verdict.NoKnownMatch ||
                hashVerdict is AntivirusEngine.Verdict.Detected) {
                hashed++ // Number of successfully computed SHA-256 hashes.
            }
            val canNativeScan = file.length() <= MAX_NATIVE_BYTES &&
                !stopped() && allocation.reserve(installedApp, archived)
            val native = if (canNativeScan) {
                nativeChecked++
                runCatching { NativeScannerBridge.scan(context, Uri.fromFile(file)) }.getOrNull()
            } else null
            val clam = native?.clamav
                ?: AntivirusEngine.Verdict.Incomplete("native-unavailable-or-limited")
            val yara = native?.yaraX
                ?: AntivirusEngine.Verdict.Incomplete("native-unavailable-or-limited")
            when (val consensus = AutomaticScanVerdicts.evaluate(hashVerdict, clam, yara)) {
                is EngineConsensus.Decision.Threat -> {
                    matched++
                    val match = consensus.detections.first().verdict
                        as AntivirusEngine.Verdict.Detected
                    if (findings.size < 20) findings.add(
                        Finding(display, match.threatName, true))
                    // A confirmed detection may coexist with an unavailable engine.
                    // The report should still expose the incomplete coverage.
                    if (consensus.incomplete.isNotEmpty()) { incomplete++; reasons(consensus.incomplete) }
                }
                is EngineConsensus.Decision.NoKnownMatch -> Unit
                is EngineConsensus.Decision.Inconclusive -> {
                    incomplete++
                    reasons(consensus.incomplete)
                    if (consensus.reason != "scan-incomplete") reason(consensus.reason)
                    if (consensus.uncorroboratedDetections.isNotEmpty() &&
                        findings.size < 20) {
                        findings.add(Finding(
                            display, "File changed between engine scans; rescan required", false))
                    }
                }
            }
            if (apk && file.length() <= 32L * 1024 * 1024 && !stopped()) {
                when (val parsed = runCatching {
                    file.inputStream().use { ApkStructureInspector().inspect(it, ::stopped) }
                }.getOrNull()) {
                    is ApkStructureInspector.Result.Complete ->
                        if (parsed.summary.unsafePaths > 0) {
                            structuralWarnings++
                            if (findings.size < 20) findings.add(
                                Finding(display, "Unsafe APK archive paths", false))
                        }
                    else -> { incomplete++; reason("apk-structure-incomplete") }
                }
            }
        }

        for (app in packages) {
            if (stopped() || apkAttempted >= limits.apkFiles) {
                truncated = true
                break
            }
            val apkPaths = (listOfNotNull(app.sourceDir) +
                (app.splitSourceDirs?.toList() ?: emptyList())).distinct()
            if (apkPaths.isEmpty()) {
                incomplete++
                continue
            }
            for (path in apkPaths) {
                if (stopped() || apkAttempted >= limits.apkFiles) {
                    truncated = true
                    break
                }
                if (!processed.add(path)) continue
                apkAttempted++
                record(File(path), app.packageName.take(96), true)
                notifyProgress("apps")
            }
        }

        if (canReadShared && !stopped()) {
            val root = Environment.getExternalStorageDirectory()
            val rootCanonical = runCatching { root.canonicalPath }.getOrNull()
            if (rootCanonical == null || !root.isDirectory || !root.canRead()) {
                incomplete++
            } else {
                val queue = ArrayDeque<Pair<File, Int>>()
                queue.add(root to 0)
                var dirs = 0
                while (queue.isNotEmpty()) {
                    if (stopped() || sharedAttempted >= limits.sharedFiles ||
                        dirs >= MAX_DIRECTORIES) {
                        truncated = true
                        break
                    }
                    val (dir, depth) = queue.removeFirst()
                    dirs++
                    val entries = runCatching { dir.listFiles() }.getOrNull()
                    if (entries == null) {
                        incomplete++
                        continue
                    }
                    for (entry in entries) {
                        if (stopped() || sharedAttempted >= limits.sharedFiles) {
                            truncated = true
                            break
                        }
                        if (runCatching { Files.isSymbolicLink(entry.toPath()) }.getOrDefault(true))
                            continue
                        val canonical = runCatching { entry.canonicalPath }.getOrNull()
                        if (canonical == null ||
                            !canonical.startsWith(rootCanonical + File.separator)) {
                            incomplete++
                            continue
                        }
                        if (entry.isDirectory) {
                            if (depth == 0 && entry.name.equals("Android", true)) {
                                // Android/data and obb are private/restricted.
                                // Scanning everything else avoids false coverage.
                                entry.listFiles()?.filterNot {
                                    it.name.equals("data", true) ||
                                        it.name.equals("obb", true)
                                }?.forEach {
                                    if (it.isDirectory && depth + 2 <= MAX_DEPTH)
                                        queue.add(it to 2)
                                }
                            } else if (depth < MAX_DEPTH) {
                                queue.add(entry to (depth + 1))
                            } else truncated = true
                            continue
                        }
                        if (!entry.isFile || !processed.add(canonical)) continue
                        sharedAttempted++
                        if (entry.name.endsWith(".apk", ignoreCase = true))
                            storedApksAttempted++
                        record(entry, entry.name.replace('\n', ' ').take(90), false)
                        notifyProgress("files")
                    }
                }
            }
        }
        if (cancelled() || stopped()) truncated = true
        progress(Progress(apkAttempted + sharedAttempted, packages.size, "done"))
        return Report(
            packages.size, apkAttempted, sharedAttempted, hashed, nativeChecked,
            matched, incomplete, structuralWarnings, truncated,
            canReadShared, signatures != null, findings,
            storedApksAttempted, allocation.installedReserved, allocation.sharedReserved, incompleteReasons.toMap()
        )
    }
}
