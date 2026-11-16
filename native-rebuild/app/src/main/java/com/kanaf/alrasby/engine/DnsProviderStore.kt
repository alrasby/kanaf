package com.kanaf.alrasby.engine

import android.content.Context
import com.kanaf.alrasby.BuildConfig

/**
 * Exactly one encrypted upstream provider is active at a time.
 * The old dns.adguard.com label is mapped to AdGuard's published hostname;
 * it is an alias, not a separate unverified TLS endpoint.
 */
object DnsProviderStore {
    const val STANDARD = "dns.adguard-dns.com"
    const val FAMILY = "family.adguard-dns.com"
    const val LEGACY = "dns.adguard.com"
    const val PLAY_SECURITY = "security.cloudflare-dns.com"
    val choices: List<String>
        get() = if (BuildConfig.KANAF_PLAY_DNS_SECURITY_ONLY)
            listOf(PLAY_SECURITY) else listOf(LEGACY, STANDARD, FAMILY)
    val defaultProvider: String
        get() = if (BuildConfig.KANAF_PLAY_DNS_SECURITY_ONLY) PLAY_SECURITY else STANDARD
    private const val PREFS = "kanaf_dns_provider_v1"
    private const val KEY = "selected_provider"

    fun canonical(host: String): String? {
        if (BuildConfig.KANAF_PLAY_DNS_SECURITY_ONLY)
            return if (host == PLAY_SECURITY) PLAY_SECURITY else null
        return when (host) {
            LEGACY, STANDARD -> STANDARD
            FAMILY -> FAMILY
            else -> null
        }
    }

    fun endpoint(host: String): String? =
        canonical(host)?.let { "https://$it/dns-query" }

    fun selected(context: Context): String {
        val raw = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .getString(KEY, defaultProvider).orEmpty()
        // A cached AdGuard preference cannot bypass Play's provider allowlist.
        return if (raw in choices) raw else defaultProvider
    }

    fun choose(context: Context, host: String): Boolean {
        if (host !in choices) return false
        return context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .edit().putString(KEY, host).commit()
    }
}
