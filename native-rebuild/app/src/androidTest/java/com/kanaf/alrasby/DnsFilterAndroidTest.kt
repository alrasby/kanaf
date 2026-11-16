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
    @Test fun ipv6DnsPacketsAreFilteredWithoutSendingUpstream() {
        val client = byteArrayOf(
            0xfd.toByte(), 0x11, 0xbe.toByte(), 0xef.toByte(), 0xca.toByte(),
            0xfe.toByte(), 0, 0, 0, 0, 0, 0, 0, 0, 0, 1
        )
        val server = client.clone().also { it[15] = 2 }
        val question = ArrayList<Byte>()
        listOf(0x22, 0x44, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0).forEach {
            question.add(it.toByte())
        }
        for (label in "ads.doubleclick.net".split('.')) {
            question.add(label.length.toByte())
            label.toByteArray(Charsets.US_ASCII).forEach { question.add(it) }
        }
        listOf(0, 0, 1, 0, 1).forEach { question.add(it.toByte()) }
        val packet = com.kanaf.alrasby.engine.DnsIpv6PacketCodec.buildUdp(
            client, server, 54213, 53, question.toByteArray()
        )!!
        var forwarded = false
        val answer = DnsFilterCore.reply(
            packet, byteArrayOf(10, 111, 222.toByte(), 2), null, server
        ) {
            forwarded = true
            null
        }!!
        val isPlay = BuildConfig.KANAF_PLAY_DNS_SECURITY_ONLY
        assertEquals(isPlay, forwarded)
        val parsed = com.kanaf.alrasby.engine.DnsIpv6PacketCodec.parseUdp(answer)!!
        assertEquals(54213, parsed.destinationPort)
        assertEquals(if (isPlay) 2 else 3, parsed.dns[3].toInt() and 15)
        assertArrayEquals(client, parsed.destinationIp)
    }

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
        val isPlay = BuildConfig.KANAF_PLAY_DNS_SECURITY_ONLY
        assertEquals(isPlay, forwarded)
        val decoded = DnsPacketCodec.parseUdp(response)!!
        assertEquals(if (isPlay) 2 else 3, decoded.dns[3].toInt() and 15)
        assertEquals(54000, decoded.destinationPort)
        assertArrayEquals(client, decoded.destinationIp)
    }
}
