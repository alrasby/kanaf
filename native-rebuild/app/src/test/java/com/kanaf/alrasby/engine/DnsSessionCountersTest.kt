package com.kanaf.alrasby.engine

import org.junit.Assert.*
import org.junit.Test

class DnsSessionCountersTest {
    private fun query(domain: String): ByteArray {
        val q = arrayListOf<Byte>()
        listOf(0x12, 0x34, 0x01, 0, 0, 1, 0, 0, 0, 0, 0, 0).forEach { q.add(it.toByte()) }
        domain.split('.').forEach { label ->
            q.add(label.length.toByte())
            label.toByteArray(Charsets.US_ASCII).forEach { q.add(it) }
        }
        listOf(0, 0, 1, 0, 1).forEach { q.add(it.toByte()) }
        return q.toByteArray()
    }

    private val client = byteArrayOf(10, 111, 222.toByte(), 1)
    private val server = byteArrayOf(10, 111, 222.toByte(), 2)
    private fun packet(host: String) =
        DnsPacketCodec.buildUdp(client, server, 53600, 53, query(host))!!

    @Test fun countsBlockedForwardedAndFailedWithoutRecordingDomains() {
        val stats = DnsSessionCounters()
        assertNotNull(DnsFilterCore.reply(packet("ads.doubleclick.net"), server, stats) {
            fail("blocked DNS must not reach upstream")
            null
        })
        val valid = DnsPacketCodec.nxdomain(query("example.com"))!!
        assertNotNull(DnsFilterCore.reply(packet("example.com"), server, stats) { valid })
        assertNotNull(DnsFilterCore.reply(packet("example.org"), server, stats) { null })
        val snapshot = stats.snapshot()
        assertEquals(1, snapshot.blocked)
        assertEquals(1, snapshot.forwarded)
        assertEquals(1, snapshot.failed)
        assertEquals(3, snapshot.total)
        assertFalse(snapshot.toString().contains("example.com"))
    }

    @Test fun unrelatedPacketsDoNotInflateStatsAndNewSessionResetsCounters() {
        val stats = DnsSessionCounters()
        assertNull(DnsFilterCore.reply(byteArrayOf(1, 2, 3), server, stats) { null })
        assertEquals(0, stats.snapshot().total)
        stats.blocked()
        assertEquals(1, stats.snapshot().total)
        assertEquals(0, DnsSessionCounters().snapshot().total)
    }
}
