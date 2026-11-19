package com.kanaf.alrasby.engine

import android.content.Context
import android.content.pm.PackageManager

/** Permission evidence is privacy exposure, never a malware diagnosis. */
object PrivacyAudit {
    data class Permission(val name: String, val granted: Boolean)
    private val sensitive = mapOf(
        "android.permission.CAMERA" to ("الكاميرا" to "Camera"),
        "android.permission.RECORD_AUDIO" to ("الميكروفون" to "Microphone"),
        "android.permission.ACCESS_FINE_LOCATION" to ("الموقع الدقيق" to "Precise location"),
        "android.permission.ACCESS_BACKGROUND_LOCATION" to ("الموقع في الخلفية" to "Background location"),
        "android.permission.READ_CONTACTS" to ("جهات الاتصال" to "Contacts"),
        "android.permission.READ_SMS" to ("قراءة الرسائل" to "Read SMS"),
        "android.permission.RECEIVE_SMS" to ("استقبال الرسائل" to "Receive SMS"),
        "android.permission.READ_CALL_LOG" to ("سجل المكالمات" to "Call history"),
        "android.permission.MANAGE_EXTERNAL_STORAGE" to ("طلب وصول شامل للملفات" to "All-files access requested"),
        "android.permission.REQUEST_INSTALL_PACKAGES" to ("طلب تثبيت تطبيقات" to "Package installation requested"),
        "android.permission.SYSTEM_ALERT_WINDOW" to ("طلب ظهور فوق التطبيقات" to "Overlay requested")
    )
    fun isSensitive(name: String) = name in sensitive
    fun describe(items: List<Permission>, arabic: Boolean): String = items.filter { isSensitive(it.name) }
        .joinToString("\n") { permission ->
            val title = sensitive.getValue(permission.name)
            val special = permission.name in setOf("android.permission.MANAGE_EXTERNAL_STORAGE",
                "android.permission.SYSTEM_ALERT_WINDOW", "android.permission.REQUEST_INSTALL_PACKAGES")
            (if (arabic) title.first else title.second) + " · " + when {
                special -> if (arabic) "راجع التفعيل في إعدادات أندرويد" else "Check active access in Android Settings"
                permission.granted -> if (arabic) "ممنوح" else "Granted"
                else -> if (arabic) "مطلوب وغير ممنوح" else "Requested, not granted"
            }
        }

    fun load(context: Context, packageName: String): List<Permission> {
        @Suppress("DEPRECATION")
        val info = context.packageManager.getPackageInfo(packageName, PackageManager.GET_PERMISSIONS)
        return info.requestedPermissions.orEmpty().mapIndexed { index, name ->
            Permission(name, ((info.requestedPermissionsFlags?.getOrNull(index) ?: 0) and
                PackageManager.REQUESTED_PERMISSION_GRANTED) != 0)
        }.filter { isSensitive(it.name) }
    }
}
