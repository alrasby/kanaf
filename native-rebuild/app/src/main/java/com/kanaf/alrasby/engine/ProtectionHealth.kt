package com.kanaf.alrasby.engine

import android.content.Context
import android.Manifest
import android.content.pm.PackageManager
import android.os.Build
import androidx.work.*
import java.util.concurrent.TimeUnit

object ProtectionHealth {
    private fun prefs(context: Context) = context.getSharedPreferences("kanaf_protection_health", Context.MODE_PRIVATE)
    fun recordScan(context: Context, matches: Int, incomplete: Int) {
        prefs(context).edit().putLong("last_scan", System.currentTimeMillis())
            .putInt("matches", matches).putInt("incomplete", incomplete).apply()
    }
    fun checkedUpdates(context: Context) {
        prefs(context).edit().putLong("last_update_check", System.currentTimeMillis()).apply()
    }
    fun autoUpdateEnabled(context: Context) = prefs(context).getBoolean("auto_update", false)
    fun setAutoUpdate(context: Context, enabled: Boolean) {
        check(!enabled || ThreatRuleUpdater().availability().configured)
        check(prefs(context).edit().putBoolean("auto_update", enabled).commit())
        if (enabled) WorkManager.getInstance(context).enqueueUniquePeriodicWork(
            "kanaf-signed-rule-updates", ExistingPeriodicWorkPolicy.UPDATE,
            PeriodicWorkRequestBuilder<SignedRuleUpdateWorker>(24, TimeUnit.HOURS)
                .setConstraints(Constraints.Builder().setRequiredNetworkType(NetworkType.CONNECTED)
                    .setRequiresBatteryNotLow(true).build()).build())
        else WorkManager.getInstance(context).cancelUniqueWork("kanaf-signed-rule-updates")
    }
    fun describe(context: Context, arabic: Boolean): String {
        val store = prefs(context)
        fun tr(ar: String, en: String) = if (arabic) ar else en
        fun state(value: Boolean) = if (value) tr("مفعل", "On") else tr("متوقف", "Off")
        fun date(key: String) = store.getLong(key, 0L).takeIf { it > 0 }?.let {
            java.text.DateFormat.getDateTimeInstance(java.text.DateFormat.SHORT, java.text.DateFormat.SHORT)
                .format(java.util.Date(it))
        } ?: tr("لم يُسجل بعد", "Not recorded")
        val repo = runCatching { SignatureRepository(context).status() }.getOrNull()
        val notifications = Build.VERSION.SDK_INT < 33 || context.checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) == PackageManager.PERMISSION_GRANTED
        return listOf(
            tr("قاعدة البصمات الموقعة", "Signed hash database") + ": " + (repo?.let { "v${it.version} · ${it.count}" } ?: tr("غير متاحة", "Unavailable")),
            tr("آخر تحقق ناجح من التحديثات", "Last successful update check") + ": " + date("last_update_check"),
            tr("التحديث اليومي بإذن المستخدم", "Opt-in daily updates") + ": " + state(autoUpdateEnabled(context)),
            tr("آخر فحص للجهاز", "Last device scan") + ": " + date("last_scan"),
            tr("تطابقات / فحوص غير مكتملة", "Matches / incomplete checks") + ": ${store.getInt("matches", 0)} / ${store.getInt("incomplete", 0)}",
            tr("حماية DNS تعمل الآن", "DNS protection currently running") + ": " + state(KanafDnsVpnService.isRunning()),
            tr("مراقبة التثبيت مفعلة", "Install scanning enabled") + ": " + state(ProtectionControl.installWatchEnabled(context)),
            tr("فحص المجلد الدوري مفعل", "Scheduled folder check enabled") + ": " + state(ProtectionControl.periodicEnabled(context)),
            tr("إذن الإشعارات", "Notification permission") + ": " + state(notifications),
            tr("المراقبة والجدولة تخضعان لقيود أندرويد والبطارية.", "Android and battery restrictions apply to monitoring and scheduling.")
        ).joinToString("\n")
    }
}

class SignedRuleUpdateWorker(context: Context, params: WorkerParameters) : Worker(context, params) {
    override fun doWork(): Result {
        if (isStopped || !ProtectionHealth.autoUpdateEnabled(applicationContext)) return Result.success()
        return try {
            ThreatRuleUpdater().update(applicationContext)
            Result.success()
        } catch (_: Exception) {
            if (runAttemptCount < 2) Result.retry() else Result.failure()
        }
    }
}
