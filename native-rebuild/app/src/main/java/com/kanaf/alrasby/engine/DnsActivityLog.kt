package com.kanaf.alrasby.engine

/** Opt-in, bounded RAM-only diagnostic history. Cleared on stop/disable.
 * Local allow-list exceptions cannot override an upstream provider's policy. */
object DnsActivityLog {
    data class Entry(val host: String, val reason: String, val source: String)
    @Volatile var enabled: Boolean = false
        private set
    @Volatile private var allowedHosts: Set<String> = emptySet()
    private val entries = java.util.ArrayDeque<Entry>()
    fun validHost(raw: String): String? {
        val host = raw.trim().trimEnd('.').lowercase(java.util.Locale.ROOT)
        return host.takeIf { it.length <= 253 && it.contains('.') && it.split('.').all { label ->
            label.matches(Regex("[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"))
        } }
    }
    fun setAllowed(hosts: Set<String>) {
        require(hosts.size <= 50 && hosts.all { validHost(it) == it })
        allowedHosts = hosts.toSet()
    }
    fun allowed() = allowedHosts.toSet()
    fun locallyAllowed(host: String) = host.trimEnd('.').lowercase(java.util.Locale.ROOT) in allowedHosts
    @Synchronized fun setEnabled(value: Boolean) { enabled = value; if (!value) entries.clear() }
    @Synchronized fun record(host: String, reason: String, source: String) {
        if (!enabled || validHost(host) == null) return
        if (entries.size == 64) entries.removeFirst()
        entries.addLast(Entry(host, reason.take(80), source.take(80)))
    }
    @Synchronized fun snapshot() = entries.toList().asReversed()
    @Synchronized fun clear() { entries.clear() }
}
