package com.kanaf.alrasby.engine

import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.provider.Settings
import java.util.Locale

/**
 * On-demand inventory of LAUNCHABLE apps visible under Android 11+ package
 * visibility rules. No QUERY_ALL_PACKAGES, no package scanning, no telemetry,
 * and no hidden app/permission control.
 */
class InstalledAppInventory {
    data class Entry(
        val packageName: String,
        val displayName: String,
        val requestedPermissionCount: Int?
    )

    private val validPackage = Regex("[A-Za-z_][A-Za-z0-9_]*(\\.[A-Za-z_][A-Za-z0-9_]*)+")

    fun load(context: Context): List<Entry> {
        val manager = context.packageManager
        val launcher = Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_LAUNCHER)
        val visible = manager.queryIntentActivities(launcher, 0)
        return visible.asSequence().mapNotNull { found ->
            val info = found.activityInfo ?: return@mapNotNull null
            val name = info.packageName ?: return@mapNotNull null
            if (!info.enabled || !info.applicationInfo.enabled || !validPackage.matches(name)) {
                return@mapNotNull null
            }
            val count = try {
                manager.getPackageInfo(name, PackageManager.GET_PERMISSIONS)
                    .requestedPermissions?.size ?: 0
            } catch (_: Exception) {
                null
            }
            val label = runCatching { found.loadLabel(manager).toString() }
                .getOrDefault(name)
                .replace('\n', ' ')
                .trim()
                .take(80)
                .ifBlank { name }
            Entry(name, label, count)
        }.distinctBy { it.packageName }
            .sortedWith(compareBy(String.CASE_INSENSITIVE_ORDER) { it.displayName })
            .toList()
    }

    /** Android, not Kanaf, handles any permission or disable decision. */
    fun settingsIntent(packageName: String): Intent {
        require(validPackage.matches(packageName)) { "Invalid package name" }
        return Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS,
            Uri.parse("package:$packageName"))
    }
}
