package com.kanaf.alrasby

import androidx.test.ext.junit.runners.AndroidJUnit4
import com.kanaf.alrasby.engine.DnsFilterCore
import com.kanaf.alrasby.engine.DnsPacketCodec
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith

/** Executes the DNS VPN's real, local packet policy on Android without VPN consent. */
@RunWith(AndroidJUnit4::class)
class DnsFilterAndroidTest {
    @Test fun blockedDomainYieldsLocalNxdomainWithNoUpstreamRequest() {
        val query = ArrayList<Byte>()
        listOf(0x12, 0x34, 0x01, 0, 0, 1, 0, 0, 0, 0, 0, 0).forEach {
            query.add(it.toByte())
        }
        for (label in "ads.doubleclick.net".split('.')) {
            query.add(label.length.toByte())
            label.toByteArray(Charsets.US_ASCII).forEach { query.add(it) }
        }
        listOf(0, 0, 1, 0, 1).forEach { query.add(it.toByte()) }
        val client = byteArrayOf(10, 111, 222.toByte(), 1)
        val server = byteArrayOf(10, 111, 222.toByte(), 2)
        val packet = DnsPacketCodec.buildUdp(client, server, 54000, 53, query.toByteArray())!!
        var forwarded = false
        val response = DnsFilterCore.reply(packet, server) {
            forwarded = true
            null
        }!!
        assertFalse(forwarded)
        val decoded = DnsPacketCodec.parseUdp(response)!!
        assertEquals(3, decoded.dns[3].toInt() and 15)
        assertEquals(54000, decoded.destinationPort)
        assertArrayEquals(client, decoded.destinationIp)
    }
}
