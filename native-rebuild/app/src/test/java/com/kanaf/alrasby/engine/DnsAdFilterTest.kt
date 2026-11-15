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
        val src = byteArrayOf(10,111,222,2)
        val dst = byteArrayOf(10,111,222,1)
        val packet = DnsPacketCodec.buildUdp(src, dst, 53, 51741, dns)!!
        val parsed = DnsPacketCodec.parseUdp(packet)!!
        assertEquals(51741, parsed.destinationPort)
        assertArrayEquals(dns, parsed.dns)
        packet[6] = 0x20
        assertNull(DnsPacketCodec.parseUdp(packet))
        assertNull(DnsPacketCodec.parseUdp(byteArrayOf(0x45)))
    }

    @Test fun malformedOrCompressedQuestionIsNotClassified() {
        val q = query("example.com")
        q[12] = 0xc0.toByte()
        assertNull(DnsPacketCodec.questionName(q))
        assertNull(DnsPacketCodec.nxdomain(q))
    }
}
