package com.kanaf.alrasby.engine

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import androidx.work.*
import org.json.JSONObject
import java.util.concurrent.TimeUnit

/** Android 8+ restricts manifest PACKAGE_ADDED/REPLACED delivery. Dynamic
 * broadcasts cover the live process; this opt-in periodic delta inventory
 * covers process death without a permanent service or scanning unchanged APKs.
 * WorkManager's 15-minute period is approximate and may be delayed by Android.
 */
object InstallWatchScheduler {
    const val NAME = "kanaf-install-inventory-v1"
    fun schedule(context: Context) {
        WorkManager.getInstance(context).enqueueUniquePeriodicWork(NAME, ExistingPeriodicWorkPolicy.KEEP,
            PeriodicWorkRequestBuilder<InstallInventoryWorker>(15, TimeUnit.MINUTES)
                .setConstraints(Constraints.Builder().setRequiresBatteryNotLow(true).build())
                .addTag(PackageReviewWorker.TAG).build())
    }
    fun cancel(context: Context) { WorkManager.getInstance(context).cancelUniqueWork(NAME) }
    fun changed(previous: Map<String, String>, current: Map<String, String>) =
        current.keys.filter { previous[it] != current[it] }.sorted()
}

class InstallInventoryWorker(context: Context, params: WorkerParameters) : Worker(context, params) {
    override fun doWork(): Result {
        val context = applicationContext
        val generation = ProtectionControl.installGeneration(context)
        fun stopped() = isStopped || !ProtectionControl.installWatchEnabled(context) ||
            ProtectionControl.installGeneration(context) != generation
        if (stopped()) return Result.success()
        val store = context.getSharedPreferences("kanaf_install_inventory", Context.MODE_PRIVATE)
        return try {
            @Suppress("DEPRECATION")
            val flags = PackageManager.GET_PERMISSIONS or if (Build.VERSION.SDK_INT >= 28)
                PackageManager.GET_SIGNING_CERTIFICATES else PackageManager.GET_SIGNATURES
            @Suppress("DEPRECATION")
            val visible = context.packageManager.getInstalledPackages(flags).sortedBy { it.packageName }
            check(visible.isNotEmpty()) { "package-inventory-unavailable" }
            val selected = visible.take(2500)
            val current = selected.associate { info ->
                @Suppress("DEPRECATION")
                val version = if (Build.VERSION.SDK_INT >= 28) info.longVersionCode else info.versionCode.toLong()
                info.packageName to "$version:${info.lastUpdateTime}"
            }
            val previous = store.getString("versions", null)?.let { text ->
                val json = JSONObject(text)
                json.keys().asSequence().associateWith { json.getString(it) }
            }
            if (stopped()) return Result.success()
            val next: Map<String, String>
            var changedCount = 0
            var queuedCount = 0
            if (previous == null) {
                // Seed once when the user opts in. Existing applications are
                // not silently mass-scanned as if they had just been installed.
                val snapshots = selected.mapNotNull { info ->
                    runCatching { info.packageName to PackageBaseline.fromPackageInfo(info) }.getOrNull()
                }.toMap()
                PackageBaseline.saveMissing(context, snapshots)
                next = current
            } else {
                val changes = InstallWatchScheduler.changed(previous, current)
                val queued = changes.take(8)
                changedCount = changes.size
                queuedCount = queued.size
                for (name in queued) {
                    if (stopped()) return Result.success()
                    WorkManager.getInstance(context).enqueueUniqueWork("kanaf-package-$name", ExistingWorkPolicy.KEEP,
                        OneTimeWorkRequestBuilder<PackageReviewWorker>().addTag(PackageReviewWorker.TAG)
                            .setInputData(workDataOf("package" to name)).build())
                        .result.get(10, TimeUnit.SECONDS)
                }
                // Unqueued changes remain pending for the next bounded cycle.
                next = current.filterKeys { it !in changes || it in queued }.toMutableMap().apply {
                    changes.filterNot { it in queued }.forEach { name -> previous[name]?.let { put(name, it) } }
                }
            }
            if (stopped()) return Result.success()
            if (!ProtectionControl.commitInventoryIfCurrent(context, generation) {
                check(store.edit().putString("versions", JSONObject(next).toString()).commit())
            }) return Result.success()
            val scope = if (visible.size > selected.size) "partial inventory; 2500-package limit" else "inventory ready"
            ProtectionControl.saveInventoryStatus(context,
                "$scope; visible=${selected.size}; changed=$changedCount; queued=$queuedCount; pending=${changedCount - queuedCount}; background interval approximately 15 min or later")
            Result.success()
        } catch (_: Exception) {
            if (!stopped()) ProtectionControl.saveInventoryStatus(context, "INCOMPLETE: installation inventory unavailable")
            if (runAttemptCount < 2) Result.retry() else Result.failure()
        }
    }
}
