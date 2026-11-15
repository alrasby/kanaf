package com.kanaf.alrasby.engine

import org.junit.Assert.*
import org.junit.Test

class DnsIpv6PacketCodecTest {
    private val client = byteArrayOf(
        0xfd.toByte(), 0x11, 0xbe.toByte(), 0xef.toByte(), 0xca.toByte(),
        0xfe.toByte(), 0, 0, 0, 0, 0, 0, 0, 0, 0, 1
    )
    private val server = client.clone().also { it[15] = 2 }

    private fun question(domain: String): ByteArray {
        val bytes = arrayListOf<Byte>()
        listOf(0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0).forEach {
            bytes.add(it.toByte())
        }
        domain.split('.').forEach { name ->
            bytes.add(name.length.toByte())
            name.toByteArray(Charsets.US_ASCII).forEach { bytes.add(it) }
        }
        listOf(0, 0, 1, 0, 1).forEach { bytes.add(it.toByte()) }
        return bytes.toByteArray()
    }

    @Test fun ipv6UdpRoundTripVerifiesChecksumAndEndpoint() {
        val dns = question("example.com")
        val packet = DnsIpv6PacketCodec.buildUdp(client, server, 51000, 53, dns)!!
        val parsed = DnsIpv6PacketCodec.parseUdp(packet)!!
        assertEquals(51000, parsed.sourcePort)
        assertEquals(53, parsed.destinationPort)
        assertArrayEquals(client, parsed.sourceIp)
        assertArrayEquals(server, parsed.destinationIp)
        assertArrayEquals(dns, parsed.dns)
        val altered = packet.clone().also { it[it.lastIndex] = (it.last().toInt() xor 1).toByte() }
        assertNull(DnsIpv6PacketCodec.parseUdp(altered))
        assertNull(DnsIpv6PacketCodec.parseUdp(packet.clone().also { it[46] = 0; it[47] = 0 }))
    }

    @Test fun rejectsUnsupportedIpv6ExtensionsTruncationAndMalformedLengths() {
        val packet = DnsIpv6PacketCodec.buildUdp(client, server, 51001, 53, question("example.com"))!!
        assertNull(DnsIpv6PacketCodec.parseUdp(packet.clone().also { it[6] = 0 }))
        assertNull(DnsIpv6PacketCodec.parseUdp(packet.clone().also { it[4] = 0; it[5] = 7 }))
        assertNull(DnsIpv6PacketCodec.parseUdp(packet.copyOf(packet.size - 1)))
        assertNull(DnsIpv6PacketCodec.buildUdp(client, server, 0, 53, question("example.com")))
        assertNull(DnsIpv6PacketCodec.buildUdp(client.copyOf(4), server, 50, 53, question("example.com")))
    }

    @Test fun ipv6DnsPolicyBlocksAdsWithoutUpstreamAndForwardsAllowedQueries() {
        val blockedRequest = DnsIpv6PacketCodec.buildUdp(
            client, server, 51234, 53, question("ads.doubleclick.net")
        )!!
        var upstream = 0
        val counts = DnsSessionCounters()
        val blocked = DnsFilterCore.reply(
            blockedRequest, byteArrayOf(10,111,222.toByte(),2), counts, server
        ) {
            upstream++
            null
        }!!
        val answer = DnsIpv6PacketCodec.parseUdp(blocked)!!
        assertEquals(51234, answer.destinationPort)
        assertEquals(3, answer.dns[3].toInt() and 15)
        assertArrayEquals(client, answer.destinationIp)
        assertEquals(0, upstream)
        assertEquals(1, counts.snapshot().blocked)

        val clean = question("example.com")
        val valid = DnsPacketCodec.nxdomain(clean)!!
        val packet = DnsIpv6PacketCodec.buildUdp(client, server, 52000, 53, clean)!!
        val forward = DnsFilterCore.reply(
            packet, byteArrayOf(10,111,222.toByte(),2), counts, server
        ) { valid }!!
        assertArrayEquals(valid, DnsIpv6PacketCodec.parseUdp(forward)!!.dns)
        assertEquals(1, counts.snapshot().forwarded)
        assertNull(DnsFilterCore.reply(packet, byteArrayOf(10,111,222.toByte(),2)) { valid })
    }

    @Test fun ipv6MalformedQuestionAndFailedUpstreamYieldServfail() {
        val malformed = question("example.com").also { it[12] = 0xc0.toByte() }
        val p = DnsIpv6PacketCodec.buildUdp(client, server, 52300, 53, malformed)!!
        val result = DnsFilterCore.reply(
            p, byteArrayOf(10,111,222.toByte(),2), null, server
        ) { null }
        assertNull(result) // cannot produce a valid DNS response to a compressed-question input
        val healthy = DnsIpv6PacketCodec.buildUdp(client, server, 52301, 53, question("example.com"))!!
        val failed = DnsFilterCore.reply(
            healthy, byteArrayOf(10,111,222.toByte(),2), null, server
        ) { null }!!
        assertEquals(2, DnsIpv6PacketCodec.parseUdp(failed)!!.dns[3].toInt() and 15)
    }
}
