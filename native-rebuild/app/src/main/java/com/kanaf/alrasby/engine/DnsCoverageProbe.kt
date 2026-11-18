package com.kanaf.alrasby.engine

import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import java.net.Inet6Address

/**
 * A bounded upstream connectivity and DNS-coverage assessment, NOT a claim
 * of full-device leak prevention. Apps may use their own DoH/DoT or IPv6 DNS.
 */
internal object DnsCoverageProbe {
    data class Result(
        val upstreamReachable: Boolean,
        val ipv6DnsConfigured: Boolean,
        val filteringActive: Boolean,
        val provider: String
    )
    fun check(context: Context, provider: String): Result {
        val reachable = DnsSecureResolver.isReachable(context, provider)
        val cm = context.getSystemService(ConnectivityManager::class.java)
        val ipv6 = cm.allNetworks.any { network ->
            val caps = cm.getNetworkCapabilities(network)
            caps != null && !caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN) &&
                cm.getLinkProperties(network)?.dnsServers?.any { it is Inet6Address } == true
        }
        return Result(reachable, ipv6, KanafDnsVpnService.isRunning(), provider)
    }
}
