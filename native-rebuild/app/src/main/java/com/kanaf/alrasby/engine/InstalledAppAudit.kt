package com.kanaf.alrasby.engine

import android.content.Context
import java.io.File

/**
 * Best-effort MANUAL review of visible installed base APK files. This is not
 * continuous or full-device antivirus scanning. Android may forbid opening
 * other packages' APKs; those are INCOMPLETE, never "clean".
 */
class InstalledAppAudit {
    data class Report(
        val candidates: Int,
        val hashed: Int,
        val matched: Int,
        val suspiciousStructure: Int,
        val incomplete: Int,
        val truncated: Boolean
    )

    fun run(context: Context, cancelled: () -> Boolean = { false }): Report {
        val visible = InstalledAppInventory().load(context)
        val selected = visible.take(20)
        val signatures = runCatching { SignatureRepository(context).load() }.getOrNull()
        var hashed = 0
        var matched = 0
        var suspicious = 0
        var incomplete = 0
        val start = android.os.SystemClock.elapsedRealtime()
        for ((index, app) in selected.withIndex()) {
            if (cancelled() || android.os.SystemClock.elapsedRealtime() - start >= 120_000L) {
                incomplete += selected.size - index
                break
            }
            try {
                val info = context.packageManager.getApplicationInfo(app.packageName, 0)
                val apk = File(info.sourceDir)
                if (!apk.isFile || !apk.canRead() || apk.length() !in 1L..(16L * 1024 * 1024)) {
                    incomplete++
                    continue
                }
                val verdict = HashSignatureEngine(signatures).scan({ apk.inputStream() }, cancelled)
                when (verdict) {
                    is AntivirusEngine.Verdict.Detected -> matched++
                    is AntivirusEngine.Verdict.NoKnownMatch -> hashed++
                    is AntivirusEngine.Verdict.Incomplete -> { incomplete++; continue }
                }
                val structure = apk.inputStream().use { ApkStructureInspector().inspect(it) }
                val dex = apk.inputStream().use { DexHeaderInspector().inspect(it) }
                val zip = apk.inputStream().use { ZipInspector().inspect(it) }
                if (structure is ApkStructureInspector.Result.Complete &&
                    dex is DexHeaderInspector.Result.Complete &&
                    zip is ZipInspector.Result.Complete) {
                    if (structure.summary.unsafePaths > 0 ||
                        dex.summary.invalidHeaders > 0 ||
                        zip.summary.unsafeNames > 0) suspicious++
                } else incomplete++
                // A split APK contains more code/resources than the base APK.
                if (!info.splitSourceDirs.isNullOrEmpty()) incomplete++
            } catch (_: Exception) { incomplete++ }
        }
        return Report(visible.size, hashed, matched, suspicious,
            incomplete, visible.size > selected.size)
    }
}
