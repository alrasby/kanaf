package com.kanaf.alrasby.engine

import org.junit.Assert.*
import org.junit.Test

class DnsAdFilterTest {
    private fun query(domain: String): ByteArray {
        val output = ArrayList<Byte>()
        listOf(0x12,0x34,0x01,0,0,1,0,0,0,0,0,0).forEach { output.add(it.toByte()) }
        domain.split('.').forEach { label ->
            output.add(label.length.toByte())
            label.toByteArray(Charsets.US_ASCII).forEach { output.add(it) }
        }
        listOf(0,0,1,0,1).forEach { output.add(it.toByte()) }
        return output.toByteArray()
    }

    @Test fun matchingIsDomainBoundedNotSubstring() {
        assertTrue(AdDomainRules.isAdOrTracker("ads.doubleclick.net"))
        assertTrue(AdDomainRules.isAdOrTracker("DOUBLECLICK.NET."))
        assertFalse(AdDomainRules.isAdOrTracker("doubleclick.net.evil.example"))
        assertFalse(AdDomainRules.isAdOrTracker("https://doubleclick.net"))
        assertFalse(AdDomainRules.isAdOrTracker("example.com"))
    }

    @Test fun nxdomainKeepsQuestionAndTransactionId() {
        val request = query("ads.doubleclick.net")
        assertEquals("ads.doubleclick.net", DnsPacketCodec.questionName(request))
        val response = DnsPacketCodec.nxdomain(request)!!
        assertEquals(0x12, response[0].toInt() and 255)
        assertEquals(0x34, response[1].toInt() and 255)
        assertEquals(3, response[3].toInt() and 15)
        assertEquals(1, response[5].toInt() and 255)
        assertEquals(0, response[7].toInt() and 255)
    }

    @Test fun validUdpPacketAndFragmentsAreHandledSafely() {
        val dns = query("example.com")
        val src = byteArrayOf(10, 111, 222.toByte(), 2)
        val dst = byteArrayOf(10, 111, 222.toByte(), 1)
        val packet = DnsPacketCodec.buildUdp(src, dst, 53, 51741, dns)!!
        val parsed = DnsPacketCodec.parseUdp(packet)!!
        assertEquals(51741, parsed.destinationPort)
        assertArrayEquals(dns, parsed.dns)
        packet[6] = 0x20
        assertNull(DnsPacketCodec.parseUdp(packet))
        assertNull(DnsPacketCodec.parseUdp(byteArrayOf(0x45)))
    }

    @Test fun upstreamResponseMustMatchOriginalQuestion() {
        val question = query("example.com")
        val answer = question.copyOf().also {
            it[2] = 0x81.toByte()
            it[3] = 0x80.toByte()
        }
        assertTrue(DnsPacketCodec.matchesResponse(question, answer))
        val alteredId = answer.copyOf().also { it[1] = 0x35 }
        assertFalse(DnsPacketCodec.matchesResponse(question, alteredId))
        val alteredName = answer.copyOf().also { it[13] = 'x'.code.toByte() }
        assertFalse(DnsPacketCodec.matchesResponse(question, alteredName))
        val alteredType = answer.copyOf().also { it[it.size - 4] = 0x1c }
        assertFalse(DnsPacketCodec.matchesResponse(question, alteredType))
        val notAResponse = question.copyOf()
        assertFalse(DnsPacketCodec.matchesResponse(question, notAResponse))
    }

    @Test fun blockedQueryUsesActualVpnPolicyWithoutForwarding() {
        val client = byteArrayOf(10, 111, 222.toByte(), 1)
        val server = byteArrayOf(10, 111, 222.toByte(), 2)
        val packet = DnsPacketCodec.buildUdp(
            client, server, 53001, 53, query("ads.doubleclick.net"))!!
        var calls = 0
        val reply = DnsFilterCore.reply(packet, server) { calls++; null }!!
        val isPlay = com.kanaf.alrasby.BuildConfig.KANAF_PLAY_DNS_SECURITY_ONLY
        assertEquals(if (isPlay) 1 else 0, calls)
        val decoded = DnsPacketCodec.parseUdp(reply)!!
        assertEquals(53001, decoded.destinationPort)
        // Play DNS forwards ads; null upstream fails as SERVFAIL, not NXDOMAIN.
        assertEquals(if (isPlay) 2 else 3, decoded.dns[3].toInt() and 15)
        assertArrayEquals(client, decoded.destinationIp)
    }

    @Test fun goodUpstreamResponsePassesButForgedIdReturnsServfail() {
        val client = byteArrayOf(10, 111, 222.toByte(), 1)
        val server = byteArrayOf(10, 111, 222.toByte(), 2)
        val dns = query("example.com")
        val packet = DnsPacketCodec.buildUdp(client, server, 53002, 53, dns)!!
        val valid = DnsPacketCodec.nxdomain(dns)!!
        assertArrayEquals(valid, DnsPacketCodec.parseUdp(
            DnsFilterCore.reply(packet, server) { valid }!!)!!.dns)
        val forged = valid.copyOf().also { it[1] = 13 }
        assertEquals(2, DnsPacketCodec.parseUdp(
            DnsFilterCore.reply(packet, server) { forged }!!)!!.dns[3].toInt() and 15)
        assertEquals(2, DnsPacketCodec.parseUdp(
            DnsFilterCore.reply(packet, server) { null }!!)!!.dns[3].toInt() and 15)
    }

    @Test fun unsolicitedDnsResponseIsNotForwarded() {
        val client = byteArrayOf(10, 111, 222.toByte(), 1)
        val server = byteArrayOf(10, 111, 222.toByte(), 2)
        val packet = DnsPacketCodec.buildUdp(
            client, server, 53003, 53,
            DnsPacketCodec.nxdomain(query("example.com"))!!
        )!!
        var used = false
        assertNull(DnsFilterCore.reply(packet, server) { used = true; null })
        assertFalse(used)
    }

    @Test fun serviceDiscoveryAndRootQueriesRemainForwardable() {
        val client = byteArrayOf(10, 111, 222.toByte(), 1)
        val server = byteArrayOf(10, 111, 222.toByte(), 2)
        for (domain in listOf("_sip._tcp.example.com", "")) {
            val dns = query(domain)
            assertEquals(domain, DnsPacketCodec.questionName(dns))
            assertFalse(AdDomainRules.isAdOrTracker(domain))
            val packet = DnsPacketCodec.buildUdp(client, server, 53555, 53, dns)!!
            val remote = DnsPacketCodec.nxdomain(dns)!!
            var forwarded = 0
            val answer = DnsFilterCore.reply(packet, server) {
                forwarded++
                remote
            }!!
            assertEquals(1, forwarded)
            assertArrayEquals(remote, DnsPacketCodec.parseUdp(answer)!!.dns)
        }
    }

    @Test fun malformedOrCompressedQuestionIsNotClassified() {
        val q = query("example.com")
        q[12] = 0xc0.toByte()
        assertNull(DnsPacketCodec.questionName(q))
        assertNull(DnsPacketCodec.nxdomain(q))
    }
}
