package com.kanaf.alrasby.engine

import android.content.Context

/**
 * Public Kanaf never requires ADB, root or WRITE_SECURE_SETTINGS.
 * Android Private DNS Off and Automatic coexist with the encrypted
 * DNS-over-HTTPS resolver; strict provider mode takes precedence.
 */
object PrivateDnsToggle {
    enum class Decision { READY, MANUAL_REQUIRED }

    fun decision(state: PrivateDnsCompatibility.Snapshot): Decision =
        if (state.allowsLocalVpn) Decision.READY else Decision.MANUAL_REQUIRED

    fun granted(context: Context) = false
    fun prepare(context: Context): Boolean =
        PrivateDnsCompatibility.read(context).allowsLocalVpn
    // Compatibility for existing installed preview sessions; never writes settings.
    fun pending(context: Context) = false
    fun restoreAuto(context: Context) = true
    fun recoverIfStopped(context: Context) = Unit
}
