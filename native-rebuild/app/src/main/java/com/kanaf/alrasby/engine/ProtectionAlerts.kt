package com.kanaf.alrasby.engine

import android.Manifest
import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import com.kanaf.alrasby.MainActivity
import com.kanaf.alrasby.KanafUiPreferences

/** Generic, local alerts without leaking file paths or private document names. */
object ProtectionAlerts {
    private const val CHANNEL = "kanaf_opt_in_security_events"

    /** Event IDs carry no filenames or package metadata into notifications. */
    internal fun localizedEvent(
        id: Int, arabic: Boolean, fallbackTitle: String, fallbackMessage: String
    ): Pair<String, String> = if (!arabic) {
        fallbackTitle to fallbackMessage
    } else when (id) {
        12001 -> "فحص كنف المجدول غير مكتمل" to
            "انتهى إذن الوصول إلى المجلد المحدد. راجع إعدادات الحماية."
        12002 -> "مطابقة بصمة محلية في كنف" to
            "راجع المجلد المحدد في كنف. المطابقة لا تعادل تقييم مكافحة فيروسات شامل."
        12003 -> "تعذر استكمال فحص كنف" to
            "تعذر فحص بعض ملفات المجلد الذي اخترته."
        12004 -> "مراجعة تطبيق جديد في كنف" to
            "استُلم إشعار تثبيت أو تحديث تطبيق. افتح كنف لمراجعته يدويًا."
        else -> fallbackTitle to fallbackMessage
    }

    fun post(context: Context, id: Int, title: String, message: String) {
        if (Build.VERSION.SDK_INT >= 33 &&
            context.checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) !=
                PackageManager.PERMISSION_GRANTED) return
        val arabic = KanafUiPreferences(context).language().isArabic()
        val text = localizedEvent(id, arabic, title, message)
        val manager = context.getSystemService(NotificationManager::class.java) ?: return
        manager.createNotificationChannel(NotificationChannel(
            CHANNEL, if (arabic) "مراجعات الأمان من كنف" else "Kanaf security review",
            NotificationManager.IMPORTANCE_DEFAULT
        ))
        val open = PendingIntent.getActivity(context, 0,
            Intent(context, MainActivity::class.java)
                .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE)
        val notification = Notification.Builder(context, CHANNEL)
            .setSmallIcon(com.kanaf.alrasby.R.drawable.kanaf_launcher_legacy)
            .setContentTitle(text.first.take(80))
            .setContentText(text.second.take(180))
            .setContentIntent(open)
            .setAutoCancel(true)
            .build()
        manager.notify(id, notification)
    }
}
