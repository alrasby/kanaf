package com.kanaf.alrasby.engine

import java.util.concurrent.atomic.AtomicLong

/**
 * Ephemeral, aggregate-only DNS statistics. Never stores hostnames, queries,
 * IP addresses, or timestamps. Counters are discarded when the VPN stops.
 */
class DnsSessionCounters {
    data class Snapshot(val blocked: Long, val forwarded: Long, val failed: Long) {
        val total: Long get() = blocked + forwarded + failed
    }

    private val blockedCount = AtomicLong()
    private val forwardedCount = AtomicLong()
    private val failedCount = AtomicLong()

    fun blocked() { blockedCount.incrementAndGet() }
    fun forwarded() { forwardedCount.incrementAndGet() }
    fun failed() { failedCount.incrementAndGet() }
    fun snapshot() = Snapshot(blockedCount.get(), forwardedCount.get(), failedCount.get())
}
