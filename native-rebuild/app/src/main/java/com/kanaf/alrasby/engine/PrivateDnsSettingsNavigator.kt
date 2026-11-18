package com.kanaf.alrasby.engine

import android.app.Activity
import android.content.Context
import android.content.Intent
import android.provider.Settings

/** Samsung/Android variants may not expose a public deep-link for Private DNS. */
object PrivateDnsSettingsNavigator {
    fun open(context: Context): Boolean {
        val actions = listOf(
            "android.settings.PRIVATE_DNS_SETTINGS",
            Settings.ACTION_WIRELESS_SETTINGS,
            Settings.ACTION_SETTINGS
        )
        for (action in actions) {
            try {
                val intent = Intent(action)
                if (context !is Activity) intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                context.startActivity(intent)
                return true
            } catch (_: Exception) {
                // Unsupported/blocked OEM deep link: use the next system Settings page.
            }
        }
        return false
    }
}
