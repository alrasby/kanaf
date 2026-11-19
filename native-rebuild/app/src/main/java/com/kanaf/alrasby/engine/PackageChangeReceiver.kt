package com.kanaf.alrasby.engine

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.net.Uri
import androidx.work.*
import java.io.File

/** Opt-in, OS-scheduled package scanning. No polling or permanent background service. */
class PackageChangeReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (!ProtectionControl.installWatchEnabled(context)) return
        if (intent.action != Intent.ACTION_PACKAGE_ADDED && intent.action != Intent.ACTION_PACKAGE_REPLACED) return
        if (intent.action == Intent.ACTION_PACKAGE_ADDED && intent.getBooleanExtra(Intent.EXTRA_REPLACING, false)) return
        val name = intent.data?.takeIf { it.scheme == "package" }?.schemeSpecificPart ?: return
        if (!name.matches(Regex("[A-Za-z_][A-Za-z0-9_]*(\\.[A-Za-z_][A-Za-z0-9_]*)+"))) return
        WorkManager.getInstance(context.applicationContext).enqueueUniqueWork(
            "kanaf-package-$name", ExistingWorkPolicy.REPLACE,
            OneTimeWorkRequestBuilder<PackageReviewWorker>().addTag(PackageReviewWorker.TAG)
                .setInputData(workDataOf("package" to name)).build())
    }
}

class PackageReviewWorker(context: Context, params: WorkerParameters) : Worker(context, params) {
    companion object { const val TAG = "kanaf-install-scan-v1" }
    override fun doWork(): Result {
        val context = applicationContext
        fun stopped() = isStopped || !ProtectionControl.installWatchEnabled(context)
        if (stopped()) return Result.success()
        val name = inputData.getString("package") ?: return Result.failure()
        val lines = ArrayList<String>()
        try {
            val before = PackageBaseline.snapshot(context, name)
            val change = PackageBaseline.inspect(context, name, before)
            lines += "Package: $name; version=${before.version}"
            lines += if (change.baselineExists) "New permissions: " + change.addedPermissions.sorted().joinToString()
                else "First observation; no previous version available for comparison"
            if (change.unverifiedSignerChange) lines += "REVIEW: signing certificate changed; lineage not verified"
            lines += PrivacyAudit.describe(PrivacyAudit.load(context, name), false)
            val signatures = runCatching { SignatureRepository(context).load() }.getOrNull()
            val engine = HashSignatureEngine(signatures, StreamScanner(maxBytes = 256L * 1024 * 1024,
                signatures = signatures ?: emptyMap()))
            val app = context.packageManager.getApplicationInfo(name, 0)
            val paths = (listOfNotNull(app.sourceDir) + app.splitSourceDirs.orEmpty()).distinct()
            val start = android.os.SystemClock.elapsedRealtime()
            var matched = 0
            var incomplete = 0
            var scanned = 0
            for (path in paths.take(32)) {
                if (stopped()) return Result.success()
                if (android.os.SystemClock.elapsedRealtime() - start > 120_000L) {
                    incomplete += paths.size - scanned
                    break
                }
                val file = File(path)
                val hash = engine.scan({ file.inputStream() }, ::stopped)
                val native = if (file.length() in 1L..(64L * 1024 * 1024))
                    NativeScannerBridge.scan(context, Uri.fromFile(file)) else null
                val result = AutomaticScanVerdicts.evaluate(hash,
                    native?.clamav ?: AntivirusEngine.Verdict.Incomplete("native-size-limit-or-unavailable"),
                    native?.yaraX ?: AntivirusEngine.Verdict.Incomplete("native-size-limit-or-unavailable"))
                when (result) {
                    is EngineConsensus.Decision.Threat -> {
                        matched++
                        lines += "MATCH: " + result.detections.joinToString { (it.verdict as AntivirusEngine.Verdict.Detected).threatName }
                        if (result.incomplete.isNotEmpty()) incomplete++
                    }
                    is EngineConsensus.Decision.Inconclusive -> incomplete++
                    is EngineConsensus.Decision.NoKnownMatch -> Unit
                }
                scanned++
            }
            if (paths.size > 32) incomplete += paths.size - 32
            if (paths.isEmpty()) incomplete++
            if (stopped()) return Result.success()
            if (before != PackageBaseline.snapshot(context, name)) {
                lines += "INCOMPLETE: package changed during scan; rescan required"
                incomplete++
            } else PackageBaseline.save(context, name, before)
            lines += "APK files checked=$scanned; known matches=$matched; incomplete=$incomplete"
            lines += "Same exact hash across engines counts as one source. No match does not establish safety. Nothing deleted."
            ProtectionControl.saveInstallResult(context, lines.joinToString("\n"))
            if (!stopped()) ProtectionAlerts.post(context, if (matched > 0) 12005 else if (incomplete > 0) 12006 else 12007, "كنف · Kanaf",
                if (matched > 0) "رُصد تطابق توقيع؛ افتح كنف للمراجعة · Signature matched"
                else if (incomplete > 0) "فحص التطبيق غير مكتمل؛ راجع كنف · App scan incomplete"
                else "اكتمل فحص التطبيق؛ التفاصيل في كنف · App scan completed")
        } catch (_: Exception) {
            if (!stopped()) ProtectionControl.saveInstallResult(context,
                "INCOMPLETE: package unavailable, changed, or scan failed; no safety verdict")
        }
        return Result.success()
    }
}
