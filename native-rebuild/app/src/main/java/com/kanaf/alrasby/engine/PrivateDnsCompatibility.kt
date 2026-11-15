package com.kanaf.alrasby.engine

import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.os.Build
import android.provider.Settings
import java.util.Locale

/**
 * Read-only Android system Private DNS detection. Never writes Global settings.
 * Default and unknown modes are NOT compatible with Kanaf's experimental
 * DNS-only VPN because the OS's encrypted resolver must take precedence.
 */
object PrivateDnsCompatibility {
    enum class Mode { OFF, AUTOMATIC, PROVIDER, UNKNOWN }

    data class Snapshot(
        val mode: Mode,
        val provider: String? = null,
        val encryptedDnsActive: Boolean = false
    ) {
        val allowsLocalVpn: Boolean
            get() = mode == Mode.OFF && !encryptedDnsActive
    }

    fun interpret(
        configuredMode: String?, defaultMode: String?,
        hostname: String?, encryptedDnsActive: Boolean = false
    ): Snapshot {
        val raw = configuredMode?.trim()?.takeIf(String::isNotEmpty)
            ?: defaultMode?.trim()?.takeIf(String::isNotEmpty)
            ?: "opportunistic"
        return when (raw.lowercase(Locale.ROOT)) {
            "off" -> Snapshot(Mode.OFF, encryptedDnsActive = encryptedDnsActive)
            "opportunistic" -> Snapshot(
                Mode.AUTOMATIC, encryptedDnsActive = encryptedDnsActive)
            "hostname" -> Snapshot(Mode.PROVIDER, hostname?.take(253),
                encryptedDnsActive)
            else -> Snapshot(Mode.UNKNOWN, encryptedDnsActive = encryptedDnsActive)
        }
    }

    fun read(context: Context): Snapshot {
        // Private DNS is introduced in Android 9/API 28. On Android 8,
        // no system Private DNS can conflict with the local VPN.
        if (Build.VERSION.SDK_INT < 28) return Snapshot(Mode.OFF)
        return try {
            val resolver = context.contentResolver
            // Android's published settings APIs permit read access, not write
            // access to Private DNS for a normal third-party application.
            val mode = Settings.Global.getString(resolver, "private_dns_mode")
            val defaultMode = Settings.Global.getString(resolver, "private_dns_default_mode")
            val hostname = Settings.Global.getString(resolver, "private_dns_specifier")
            val manager = context.getSystemService(ConnectivityManager::class.java)
            val encryptedActive = manager.allNetworks.any { network ->
                val caps = manager.getNetworkCapabilities(network)
                caps != null && !caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN) &&
                    manager.getLinkProperties(network)?.isPrivateDnsActive == true
            }
            interpret(mode, defaultMode, hostname, encryptedActive)
        } catch (_: Exception) {
            Snapshot(Mode.UNKNOWN, encryptedDnsActive = true)
        }
    }

    /** Private DNS uses a hostname (not an https:// URL, IP or UDP DNS). */
    fun validHostname(input: String): Boolean {
        val name = input.trim()
        if (name.length !in 4..253 || !name.contains('.')) return false
        val parts = name.split('.')
        if (parts.all { label -> label.all(Char::isDigit) }) return false
        return parts.all { part ->
            part.length in 1..63 &&
                part.first() != '-' && part.last() != '-' &&
                part.all { it in 'a'..'z' || it in 'A'..'Z' ||
                    it in '0'..'9' || it == '-' }
        }
    }
}
