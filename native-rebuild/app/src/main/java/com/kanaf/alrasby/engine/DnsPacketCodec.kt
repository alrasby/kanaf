package com.kanaf.alrasby.engine

import java.util.Locale

/** IPv4 UDP DNS codec with strict bounds and checksums. No network access. */
object DnsPacketCodec {
    data class Query(
        val sourceIp: ByteArray, val destinationIp: ByteArray,
        val sourcePort: Int, val destinationPort: Int, val dns: ByteArray
    )

    private fun u8(b: Byte) = b.toInt() and 255
    private fun u16(a: ByteArray, i: Int) = (u8(a[i]) shl 8) or u8(a[i + 1])
    private fun put16(a: ByteArray, i: Int, value: Int) {
        a[i] = (value ushr 8).toByte()
        a[i + 1] = value.toByte()
    }

    fun parseUdp(packet: ByteArray): Query? {
        if (packet.size < 28 || (u8(packet[0]) ushr 4) != 4) return null
        val header = (u8(packet[0]) and 15) * 4
        if (header < 20 || packet.size < header + 8) return null
        val total = u16(packet, 2)
        if (total < header + 8 || total > packet.size || u8(packet[9]) != 17) return null
        // Ignore fragmented packets instead of processing truncated payloads.
        if ((u16(packet, 6) and 0x3fff) != 0) return null
        val length = u16(packet, header + 4)
        if (length < 8 || header + length > total) return null
        return Query(
            packet.copyOfRange(12, 16), packet.copyOfRange(16, 20),
            u16(packet, header), u16(packet, header + 2),
            packet.copyOfRange(header + 8, header + length)
        )
    }

    private fun questionEnd(dns: ByteArray): Int? {
        if (dns.size < 17 || u16(dns, 4) != 1 ||
            (u8(dns[2]) and 0xf8) != 0) return null
        var at = 12
        var chars = 0
        while (true) {
            if (at >= dns.size) return null
            val size = u8(dns[at++])
            if (size == 0) break
            // Do not follow name compression pointers from untrusted DNS input.
            if (size > 63 || at + size > dns.size || chars + size > 253) return null
            at += size
            chars += size + 1
        }
        return if (at + 4 <= dns.size) at + 4 else null
    }

    fun questionName(dns: ByteArray): String? {
        questionEnd(dns) ?: return null
        var at = 12
        val labels = ArrayList<String>()
        while (true) {
            val size = u8(dns[at++])
            if (size == 0) break
            val label = dns.copyOfRange(at, at + size).toString(Charsets.US_ASCII)
                .lowercase(Locale.ROOT)
            if (label.isBlank() || label.any {
                    it !in "abcdefghijklmnopqrstuvwxyz0123456789-"
                }) return null
            labels.add(label)
            at += size
        }
        return labels.joinToString(".").takeIf { it.isNotEmpty() }
    }

    private fun errorResponse(query: ByteArray, code: Int): ByteArray? {
        val end = questionEnd(query) ?: return null
        if ((u8(query[2]) and 0x80) != 0) return null // Never respond to a response.
        val out = query.copyOfRange(0, end)
        out[2] = (0x80 or (u8(query[2]) and 0x01)).toByte() // QR + original RD
        out[3] = (0x80 or code).toByte() // RA + RCODE
        for (i in 6 until 12) out[i] = 0 // no answers, auth, additional
        return out
    }

    fun nxdomain(query: ByteArray) = errorResponse(query, 3)
    fun servfail(query: ByteArray) = errorResponse(query, 2)

    private fun checksum(data: ByteArray, start: Int, size: Int): Int {
        var sum = 0L
        var i = start
        while (i + 1 < start + size) {
            sum += u16(data, i).toLong()
            i += 2
        }
        if (i < start + size) sum += (u8(data[i]) shl 8).toLong()
        while ((sum ushr 16) != 0L) sum = (sum and 65535L) + (sum ushr 16)
        return sum.inv().toInt() and 65535
    }

    fun buildUdp(srcIp: ByteArray, dstIp: ByteArray, srcPort: Int, dstPort: Int,
                 dns: ByteArray): ByteArray? {
        if (srcIp.size != 4 || dstIp.size != 4 || dns.size !in 12..4096 ||
            srcPort !in 1..65535 || dstPort !in 1..65535) return null
        val udp = dns.size + 8
        val output = ByteArray(20 + udp)
        output[0] = 0x45
        put16(output, 2, output.size)
        output[8] = 64
        output[9] = 17
        srcIp.copyInto(output, 12)
        dstIp.copyInto(output, 16)
        put16(output, 20, srcPort)
        put16(output, 22, dstPort)
        put16(output, 24, udp)
        dns.copyInto(output, 28)
        put16(output, 10, checksum(output, 0, 20))
        // IPv4 UDP checksums are optional, but we calculate one for integrity.
        val pseudo = ByteArray(12 + udp + (udp and 1))
        srcIp.copyInto(pseudo, 0)
        dstIp.copyInto(pseudo, 4)
        pseudo[9] = 17
        put16(pseudo, 10, udp)
        output.copyInto(pseudo, 12, 20, output.size)
        val sum = checksum(pseudo, 0, pseudo.size)
        put16(output, 26, if (sum == 0) 65535 else sum)
        return output
    }
}
