package com.kanaf.alrasby.engine

import java.util.Locale

/**
 * Curated, small offline DNS host filter. Not a claim of full ad coverage.
 * Never use substring matches (e.g. ads.example.com.evil.invalid).
 * No remote list, analytics, or browsing history is collected.
 */
object AdDomainRules {
    private val domains = setOf(
        "doubleclick.net", "googlesyndication.com", "googleadservices.com",
        "adnxs.com", "adsrvr.org", "advertising.com", "rubiconproject.com",
        "pubmatic.com", "openx.net", "criteo.com", "outbrain.com",
        "taboola.com", "scorecardresearch.com", "quantserve.com",
        "app-measurement.com", "branch.io"
    )

    fun isAdOrTracker(host: String): Boolean {
        val normalized = host.trim().trimEnd('.').lowercase(Locale.ROOT)
        if (normalized.isEmpty() || normalized.length > 253 ||
            normalized.any { it !in "abcdefghijklmnopqrstuvwxyz0123456789-." }) return false
        return domains.any { normalized == it || normalized.endsWith("." + it) }
    }
}
