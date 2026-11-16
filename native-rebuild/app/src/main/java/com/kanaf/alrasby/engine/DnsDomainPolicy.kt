package com.kanaf.alrasby.engine

import com.kanaf.alrasby.BuildConfig
import java.util.Locale

enum class DnsRuleCategory { SECURITY_THREAT, AD_TRACKER, ALLOWED }

/**
 * A threat is NEVER inferred from an advertising hostname.
 * Verified local threat domains are currently absent; Play's real malware
 * protection is provided by the Cloudflare security-only DoH upstream.
 * Verified signed threat-domain feeds can be integrated independently later.
 */
class DnsDomainPolicy(
    private val verifiedThreatHosts: Set<String>,
    private val allowAdTrackerBlocking: Boolean
) {
    fun classify(raw: String): DnsRuleCategory {
        val host = raw.trim().trimEnd('.').lowercase(Locale.ROOT)
        if (host.isEmpty() || host.length > 253 ||
            host.any { it !in "abcdefghijklmnopqrstuvwxyz0123456789-." })
            return DnsRuleCategory.ALLOWED
        if (verifiedThreatHosts.any { host == it || host.endsWith(".$it") })
            return DnsRuleCategory.SECURITY_THREAT
        if (allowAdTrackerBlocking && AdDomainRules.isAdOrTracker(host))
            return DnsRuleCategory.AD_TRACKER
        return DnsRuleCategory.ALLOWED
    }
    companion object {
        fun forBuild() = DnsDomainPolicy(
            verifiedThreatHosts = emptySet(),
            allowAdTrackerBlocking = !BuildConfig.KANAF_PLAY_DNS_SECURITY_ONLY
        )
    }
}
