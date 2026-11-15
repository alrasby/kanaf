package com.kanaf.alrasby.engine

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.provider.Settings

/**
 * Optional system-DNS handoff. The user must grant WRITE_SECURE_SETTINGS
 * externally using ADB; Kanaf itself never executes root/ADB commands.
 */
object PrivateDnsToggle {
    private const val PREF = "kanaf_dns_handoff"
    private const val PENDING = "restore_auto"
    private const val MODE_KEY = "private_dns_mode"
    const val GRANT_COMMAND =
        "adb shell pm grant com.kanaf.alrasby android.permission.WRITE_SECURE_SETTINGS"

    enum class Decision { READY, AUTO_SWITCH, MANUAL_REQUIRED }

    fun granted(context: Context): Boolean = Build.VERSION.SDK_INT >= 28 &&
        context.checkSelfPermission("android.permission.WRITE_SECURE_SETTINGS") ==
            PackageManager.PERMISSION_GRANTED

    fun decision(snapshot: PrivateDnsCompatibility.Snapshot, permission: Boolean): Decision =
        when {
            snapshot.allowsLocalVpn -> Decision.READY
            snapshot.mode == PrivateDnsCompatibility.Mode.UNKNOWN -> Decision.MANUAL_REQUIRED
            permission -> Decision.AUTO_SWITCH
            else -> Decision.MANUAL_REQUIRED
        }

    private fun preferences(context: Context) =
        context.getSharedPreferences(PREF, Context.MODE_PRIVATE)

    fun pending(context: Context) =
        preferences(context).getBoolean(PENDING, false)

    fun prepare(context: Context): Boolean {
        if (Build.VERSION.SDK_INT < 28) return true
        val current = PrivateDnsCompatibility.read(context)
        if (current.allowsLocalVpn) return true
        if (decision(current, granted(context)) != Decision.AUTO_SWITCH) return false
        // Persist recovery state before touching Android system settings.
        if (!preferences(context).edit().putBoolean(PENDING, true).commit()) return false
        return try {
            val written = Settings.Global.putString(context.contentResolver, MODE_KEY, "off")
            if (written &&
                Settings.Global.getString(context.contentResolver, MODE_KEY) == "off") true
            else {
                restoreAuto(context)
                false
            }
        } catch (_: Exception) {
            restoreAuto(context)
            false
        }
    }

    /**
     * Set Auto on exit, except when the user already selected another DNS
     * provider, which must never be overwritten by a stale VPN cleanup.
     */
    fun restoreAuto(context: Context): Boolean {
        if (Build.VERSION.SDK_INT < 28) return true
        val prefs = preferences(context)
        // Check the system setting directly. NetworkCapabilities can throw
        // while mobile data/Wi-Fi changes; that must not lose a recovery marker.
        val current = runCatching {
            Settings.Global.getString(context.contentResolver, MODE_KEY)
        }.getOrNull()
        if (current == "opportunistic" || current == "hostname") {
            prefs.edit().remove(PENDING).apply()
            return true
        }
        if (current != "off") return !pending(context)
        if (!granted(context)) return !pending(context)
        return try {
            val written = Settings.Global.putString(
                context.contentResolver, MODE_KEY, "opportunistic")
            if (written &&
                Settings.Global.getString(context.contentResolver, MODE_KEY) == "opportunistic") {
                prefs.edit().remove(PENDING).apply()
                true
            } else false
        } catch (_: Exception) { false }
    }

    /** Called on next explicit UI entry after an unexpected process kill. */
    fun recoverIfStopped(context: Context) {
        if (!KanafDnsVpnService.isRunning() &&
            !KanafDnsVpnService.isStarting() && pending(context)) restoreAuto(context)
    }
}
