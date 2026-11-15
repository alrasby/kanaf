package com.kanaf.alrasby.engine

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import androidx.work.OneTimeWorkRequestBuilder
import androidx.work.WorkManager

/** Receives best-effort Android install/update events; never opens APKs silently. */
class PackageChangeReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (!ProtectionControl.installWatchEnabled(context)) return
        if (intent.action != Intent.ACTION_PACKAGE_ADDED &&
            intent.action != Intent.ACTION_PACKAGE_REPLACED) return
        if (intent.getBooleanExtra(Intent.EXTRA_REPLACING, false)) return
        WorkManager.getInstance(context.applicationContext)
            .enqueue(OneTimeWorkRequestBuilder<PackageReviewWorker>().build())
    }
}

/** A prompt to REVIEW a newly installed app, not an antivirus detection. */
class PackageReviewWorker(context: Context, params: androidx.work.WorkerParameters) :
    androidx.work.Worker(context, params) {
    override fun doWork(): Result {
        if (ProtectionControl.installWatchEnabled(applicationContext)) {
            ProtectionAlerts.post(applicationContext, 12004,
                "Kanaf application review", "A package install/update event was observed. Open Kanaf for manual review.")
        }
        return Result.success()
    }
}
