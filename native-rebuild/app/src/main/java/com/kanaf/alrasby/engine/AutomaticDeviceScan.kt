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
        val signaturesReady: Boolean, val findings: List<Finding>
    )

    companion object {
        private const val MAX_APK_FILES = 1400
        private const val MAX_SHARED_FILES = 4000
        private const val MAX_DIRECTORIES = 1600
        private const val MAX_DEPTH = 12
        private const val MAX_RUNTIME_MS = 8 * 60_000L
        private const val MAX_HASH_BYTES = 256L * 1024 * 1024
        private const val MAX_NATIVE_BYTES = 16L * 1024 * 1024
        private const val MAX_NATIVE_CHECKS = 100

        fun sharedStorageGranted(): Boolean = if (Build.VERSION.SDK_INT >= 30) {
            Environment.isExternalStorageManager()
        } else true // Android <= 10: request READ_EXTERNAL_STORAGE in the UI.
    }

    fun run(
        context: Context,
        includeSharedStorage: Boolean,
        cancelled: () -> Boolean = { false },
        progress: (Progress) -> Unit = {}
    ): Report {
        val start = SystemClock.elapsedRealtime()
        fun stopped() = cancelled() || Thread.currentThread().isInterrupted ||
            SystemClock.elapsedRealtime() - start > MAX_RUNTIME_MS

        val signatures = runCatching { SignatureRepository(context).load() }.getOrNull()
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
        var matched = 0
        var incomplete = 0
        var structuralWarnings = 0
        var truncated = false
        val findings = ArrayList<Finding>(16)
        val processed = HashSet<String>()
        var notifiedAt = 0

        fun notifyProgress(phase: String) {
            val attempted = apkAttempted + sharedAttempted
            if (attempted == 0 || attempted - notifiedAt >= 12) {
                notifiedAt = attempted
                progress(Progress(attempted, packages.size, phase))
            }
        }

        fun record(file: File, display: String, apk: Boolean) {
            if (stopped()) { truncated = true; return }
            if (!file.isFile || !file.canRead() || file.length() <= 0 ||
                file.length() > MAX_HASH_BYTES) {
                incomplete++
                return
            }
            val hash = HashSignatureEngine(
                signatures,
                StreamScanner(maxBytes = MAX_HASH_BYTES,
                    maxDurationNanos = 25_000_000_000L,
                    signatures = signatures ?: emptyMap())
            ).scan({ file.inputStream() }, ::stopped)
            when (hash) {
                is AntivirusEngine.Verdict.Detected -> {
                    matched++
                    if (findings.size < 20) findings.add(Finding(
                        display, hash.threatName, true))
                }
                is AntivirusEngine.Verdict.NoKnownMatch -> hashed++
                is AntivirusEngine.Verdict.Incomplete -> incomplete++
            }
            // Native rules can scan only <=16 MiB files. Every other file is
            // explicitly partial, not clean. Keep the worker process bounded.
            if (file.length() <= MAX_NATIVE_BYTES &&
                nativeChecked < MAX_NATIVE_CHECKS && !stopped()) {
                nativeChecked++
                val native = runCatching {
                    NativeScannerBridge.scan(context, Uri.fromFile(file))
                }.getOrNull()
                if (native == null) incomplete++
                else {
                    val verdicts = listOf(native.clamav, native.yaraX)
                    val nativeDetections = verdicts.filterIsInstance<AntivirusEngine.Verdict.Detected>()
                    if (nativeDetections.isNotEmpty()) {
                        // One file with two EICAR test-rule matches is ONE finding.
                        if (hash !is AntivirusEngine.Verdict.Detected) matched++
                        if (findings.size < 20 && hash !is AntivirusEngine.Verdict.Detected) {
                            findings.add(Finding(display, nativeDetections.first().threatName, true))
                        }
                    }
                    if (verdicts.any { it is AntivirusEngine.Verdict.Incomplete }) incomplete++
                }
            } else incomplete++
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
                    else -> incomplete++
                }
            }
        }

        for (app in packages) {
            if (stopped() || apkAttempted >= MAX_APK_FILES) {
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
                if (stopped() || apkAttempted >= MAX_APK_FILES) {
                    truncated = true
                    break
                }
                if (!processed.add(path)) continue
                apkAttempted++
                record(File(path), app.packageName.take(96), true)
                notifyProgress("apps")
            }
        }

        val canReadShared = includeSharedStorage && sharedStorageGranted()
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
                    if (stopped() || sharedAttempted >= MAX_SHARED_FILES ||
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
                        if (stopped() || sharedAttempted >= MAX_SHARED_FILES) {
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
            canReadShared, signatures != null, findings
        )
    }
}
