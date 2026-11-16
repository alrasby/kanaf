package com.kanaf.alrasby.engine

/**
 * Actual DNS-only VPN's packet policy, kept network-free for deterministic tests.
 * Never forwards policy-blocklisted or malformed queries; no telemetry is collected.
 */
object DnsFilterCore {
    fun reply(
        packet: ByteArray, localDnsAddress: ByteArray,
        counters: DnsSessionCounters? = null,
        localIpv6DnsAddress: ByteArray? = null,
        policy: DnsDomainPolicy = DnsDomainPolicy.forBuild(),
        resolver: (ByteArray) -> ByteArray?
    ): ByteArray? {
        if (localDnsAddress.size != 4 || packet.isEmpty()) return null
        // Only advertise and route the dedicated IPv6 resolver address. Do
        // not intercept any other IPv6 traffic or parse extension headers.
        if ((packet[0].toInt() and 0xff) ushr 4 == 6) {
            if (localIpv6DnsAddress?.size != 16) return null
            val query = DnsIpv6PacketCodec.parseUdp(packet) ?: return null
            if (query.destinationPort != 53 || query.sourcePort == 0 ||
                !query.destinationIp.contentEquals(localIpv6DnsAddress) ||
                query.dns.size < 12 || (query.dns[2].toInt() and 0x80) != 0) return null
            val answer = resolveQuestion(query.dns, counters, policy, resolver) ?: return null
            return DnsIpv6PacketCodec.buildUdp(
                localIpv6DnsAddress, query.sourceIp, 53, query.sourcePort, answer
            )
        }
        val query = DnsPacketCodec.parseUdp(packet) ?: return null
        if (query.destinationPort != 53 || query.sourcePort == 0 ||
            !query.destinationIp.contentEquals(localDnsAddress) ||
            query.dns.size < 12 || (query.dns[2].toInt() and 0x80) != 0) return null
        val answer = resolveQuestion(query.dns, counters, policy, resolver) ?: return null
        return DnsPacketCodec.buildUdp(
            localDnsAddress, query.sourceIp, 53, query.sourcePort, answer
        )
    }

    private fun resolveQuestion(
        question: ByteArray, counters: DnsSessionCounters?,
        policy: DnsDomainPolicy, resolver: (ByteArray) -> ByteArray?
    ): ByteArray? {
        val host = DnsPacketCodec.questionName(question)
        val answer = when {
            host == null -> { counters?.failed(); DnsPacketCodec.servfail(question) }
            policy.classify(host) != DnsRuleCategory.ALLOWED -> {
                counters?.blocked()
                DnsPacketCodec.nxdomain(question)
            }
            else -> {
                val upstream = runCatching { resolver(question) }.getOrNull()
                if (upstream != null &&
                    DnsPacketCodec.matchesResponse(question, upstream)) {
                    counters?.forwarded()
                    upstream
                } else {
                    counters?.failed()
                    DnsPacketCodec.servfail(question)
                }
            }
        }
        return answer
    }
}
