package com.kanaf.alrasby.engine

import android.content.Context
import android.net.Uri
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.ExistingWorkPolicy
import androidx.work.OneTimeWorkRequestBuilder
import androidx.work.WorkManager
import java.util.concurrent.TimeUnit

/** Android-supported, explicit opt-in protections. Not full-device realtime AV. */
object ProtectionControl {
    private const val PREFS = "kanaf_opt_in_protection"
    private const val WATCH_INSTALLS = "watch_package_events"
    private const val PERIODIC = "periodic_tree_checks"
    private const val TREE = "granted_tree_uri"
    private const val SUMMARY = "last_check_summary"
    const val IMMEDIATE_CHECK = "kanaf_scoped_immediate_sha256_v1"
    private const val SCHEDULE = "kanaf_scoped_periodic_sha256_v1"

    private fun prefs(context: Context) =
        context.applicationContext.getSharedPreferences(PREFS, Context.MODE_PRIVATE)

    fun installWatchEnabled(context: Context): Boolean =
        prefs(context).getBoolean(WATCH_INSTALLS, false)

    fun lastInstallResult(context: Context): String = prefs(context).getString("last_install_scan", "") ?: ""

    fun saveInstallResult(context: Context, report: String) {
        prefs(context).edit().putString("last_install_scan", report.take(12_000)).apply()
    }

    fun periodicEnabled(context: Context): Boolean =
        prefs(context).getBoolean(PERIODIC, false)

    fun permittedTree(context: Context): Uri? =
        prefs(context).getString(TREE, null)?.let(Uri::parse)

    fun lastResult(context: Context): String =
        prefs(context).getString(SUMMARY, "No scheduled check has completed") ?: ""

    fun setInstallWatch(context: Context, enabled: Boolean) {
        prefs(context).edit().putBoolean(WATCH_INSTALLS, enabled).commit()
        if (!enabled) WorkManager.getInstance(context).cancelAllWorkByTag(PackageReviewWorker.TAG)
    }

    /** Only accept a URI grant actually persisted by Android. */
    fun enableTreeChecks(context: Context, tree: Uri) {
        require(tree.scheme == "content")
        require(context.contentResolver.persistedUriPermissions.any {
            it.uri == tree && it.isReadPermission
        }) { "Tree read permission was not persisted" }
        val previous = permittedTree(context)
        val previouslyEnabled = periodicEnabled(context)
        prefs(context).edit().putString(TREE, tree.toString()).putBoolean(PERIODIC, true).commit()
        try {
            schedule(context)
        } catch (failure: Exception) {
            prefs(context).edit().putBoolean(PERIODIC, previouslyEnabled)
                .apply { if (previous == null) remove(TREE) else putString(TREE, previous.toString()) }
                .commit()
            throw failure
        }
        if (previous != null && previous != tree) {
            runCatching { context.contentResolver.releasePersistableUriPermission(
                previous, android.content.Intent.FLAG_GRANT_READ_URI_PERMISSION) }
        }
    }

    fun schedule(context: Context) {
        if (!periodicEnabled(context) || permittedTree(context) == null) return
        val request = PeriodicWorkRequestBuilder<ScopedFileCheckWorker>(24, TimeUnit.HOURS).build()
        WorkManager.getInstance(context).enqueueUniquePeriodicWork(
            SCHEDULE, ExistingPeriodicWorkPolicy.UPDATE, request
        )
    }

    fun checkNow(context: Context) {
        check(periodicEnabled(context) && permittedTree(context) != null)
        WorkManager.getInstance(context).enqueueUniqueWork(
            IMMEDIATE_CHECK, ExistingWorkPolicy.KEEP,
            OneTimeWorkRequestBuilder<ScopedFileCheckWorker>().build()
        )
    }

    fun disableTreeChecks(context: Context) {
        val previous = permittedTree(context)
        // Opt-out must be durable BEFORE cancellation; a queued worker checks
        // this flag even if WorkManager cancellation is delayed.
        prefs(context).edit().putBoolean(PERIODIC, false).remove(TREE).commit()
        runCatching { WorkManager.getInstance(context).cancelUniqueWork(SCHEDULE) }
        runCatching { WorkManager.getInstance(context).cancelUniqueWork(IMMEDIATE_CHECK) }
        if (previous != null) runCatching {
            context.contentResolver.releasePersistableUriPermission(
                previous, android.content.Intent.FLAG_GRANT_READ_URI_PERMISSION)
        }
        // Android may have already removed the provider; scheduling stays off.
    }

    fun saveResult(context: Context, message: String) {
        prefs(context).edit().putString(SUMMARY, message.take(250)).apply()
    }
}
