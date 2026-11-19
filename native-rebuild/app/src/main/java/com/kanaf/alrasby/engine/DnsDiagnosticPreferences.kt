package com.kanaf.alrasby.engine

import android.content.Context

object DnsDiagnosticPreferences {
    private fun prefs(context: Context) = context.getSharedPreferences("kanaf_dns_diagnostics", Context.MODE_PRIVATE)
    fun initialize(context: Context) {
        DnsActivityLog.setAllowed(prefs(context).getStringSet("local_exceptions", emptySet()).orEmpty())
        DnsActivityLog.setEnabled(prefs(context).getBoolean("enabled", false))
    }
    fun setEnabled(context: Context, enabled: Boolean) {
        check(prefs(context).edit().putBoolean("enabled", enabled).commit())
        DnsActivityLog.setEnabled(enabled)
    }
    fun setAllowed(context: Context, hosts: Set<String>) {
        require(hosts.size <= 50 && hosts.all { DnsActivityLog.validHost(it) == it })
        check(prefs(context).edit().putStringSet("local_exceptions", hosts.toSet()).commit())
        DnsActivityLog.setAllowed(hosts)
    }
}
