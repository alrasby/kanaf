package com.kanaf.alrasby.engine

import android.content.Context
import android.net.Uri
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.WorkManager
import java.util.concurrent.TimeUnit

/** Android-supported, explicit opt-in protections. Not full-device realtime AV. */
object ProtectionControl {
    private const val PREFS = "kanaf_opt_in_protection"
    private const val WATCH_INSTALLS = "watch_package_events"
    private const val PERIODIC = "periodic_tree_checks"
    private const val TREE = "granted_tree_uri"
    private const val SUMMARY = "last_check_summary"
    private const val SCHEDULE = "kanaf_scoped_periodic_sha256_v1"

    private fun prefs(context: Context) =
        context.applicationContext.getSharedPreferences(PREFS, Context.MODE_PRIVATE)

    fun installWatchEnabled(context: Context): Boolean =
        prefs(context).getBoolean(WATCH_INSTALLS, false)

    fun periodicEnabled(context: Context): Boolean =
        prefs(context).getBoolean(PERIODIC, false)

    fun permittedTree(context: Context): Uri? =
        prefs(context).getString(TREE, null)?.let(Uri::parse)

    fun lastResult(context: Context): String =
        prefs(context).getString(SUMMARY, "No scheduled check has completed") ?: ""

    fun setInstallWatch(context: Context, enabled: Boolean) {
        prefs(context).edit().putBoolean(WATCH_INSTALLS, enabled).apply()
    }

    /** Only accept a URI grant actually persisted by Android. */
    fun enableTreeChecks(context: Context, tree: Uri) {
        require(tree.scheme == "content")
        require(context.contentResolver.persistedUriPermissions.any {
            it.uri == tree && it.isReadPermission
        }) { "Tree read permission was not persisted" }
        prefs(context).edit().putString(TREE, tree.toString()).putBoolean(PERIODIC, true).apply()
        schedule(context)
    }

    fun schedule(context: Context) {
        if (!periodicEnabled(context) || permittedTree(context) == null) return
        val request = PeriodicWorkRequestBuilder<ScopedFileCheckWorker>(24, TimeUnit.HOURS).build()
        WorkManager.getInstance(context).enqueueUniquePeriodicWork(
            SCHEDULE, ExistingPeriodicWorkPolicy.UPDATE, request
        )
    }

    fun disableTreeChecks(context: Context) {
        WorkManager.getInstance(context).cancelUniqueWork(SCHEDULE)
        prefs(context).edit().putBoolean(PERIODIC, false).remove(TREE).apply()
        // Revocation may fail if provider was already removed; never keep an
        // active scan schedule after the user opts out.
    }

    fun saveResult(context: Context, message: String) {
        prefs(context).edit().putString(SUMMARY, message.take(250)).apply()
    }
}
