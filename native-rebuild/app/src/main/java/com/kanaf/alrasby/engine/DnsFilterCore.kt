package com.kanaf.alrasby.engine

/**
 * Actual DNS-only VPN's packet policy, kept network-free for deterministic tests.
 * Never forwards ad-blocklisted or malformed queries; no telemetry is collected.
 */
object DnsFilterCore {
    fun reply(
        packet: ByteArray, localDnsAddress: ByteArray,
        counters: DnsSessionCounters? = null,
        resolver: (ByteArray) -> ByteArray?
    ): ByteArray? {
        if (localDnsAddress.size != 4) return null
        val query = DnsPacketCodec.parseUdp(packet) ?: return null
        if (query.destinationPort != 53 || query.sourcePort == 0 ||
            !query.destinationIp.contentEquals(localDnsAddress) ||
            query.dns.size < 12 || (query.dns[2].toInt() and 0x80) != 0) return null
        val host = DnsPacketCodec.questionName(query.dns)
        val answer = when {
            host == null -> { counters?.failed(); DnsPacketCodec.servfail(query.dns) }
            AdDomainRules.isAdOrTracker(host) -> {
                counters?.blocked()
                DnsPacketCodec.nxdomain(query.dns)
            }
            else -> {
                val upstream = runCatching { resolver(query.dns) }.getOrNull()
                if (upstream != null &&
                    DnsPacketCodec.matchesResponse(query.dns, upstream)) {
                    counters?.forwarded()
                    upstream
                } else {
                    counters?.failed()
                    DnsPacketCodec.servfail(query.dns)
                }
            }
        } ?: return null
        return DnsPacketCodec.buildUdp(
            localDnsAddress, query.sourceIp, 53, query.sourcePort, answer
        )
    }
}
