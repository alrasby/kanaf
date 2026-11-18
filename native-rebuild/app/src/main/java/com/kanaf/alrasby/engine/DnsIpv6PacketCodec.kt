package com.kanaf.alrasby.engine

/**
 * DNS-only IPv6/UDP framing. Only direct UDP datagrams are supported;
 * IPv6 extension headers/fragments and malformed checksums fail closed.
 */
object DnsIpv6PacketCodec {
    data class Query(
        val sourceIp: ByteArray, val destinationIp: ByteArray,
        val sourcePort: Int, val destinationPort: Int, val dns: ByteArray
    )

    private fun u8(b: Byte) = b.toInt() and 0xff
    private fun u16(b: ByteArray, offset: Int) =
        (u8(b[offset]) shl 8) or u8(b[offset + 1])

    private fun write16(b: ByteArray, offset: Int, value: Int) {
        b[offset] = (value ushr 8).toByte()
        b[offset + 1] = value.toByte()
    }

    private fun addBytes(data: ByteArray, start: Int, size: Int, initial: Long): Long {
        var sum = initial
        var i = start
        val end = start + size
        while (i + 1 < end) {
            sum += u16(data, i).toLong()
            i += 2
        }
        if (i < end) sum += (u8(data[i]).toLong() shl 8)
        return sum
    }

    /** Returns 0 when the supplied UDP datagram already has a valid checksum. */
    private fun udpChecksum(sourceIp: ByteArray, destIp: ByteArray, udp: ByteArray): Int {
        var sum = addBytes(sourceIp, 0, 16, 0)
        sum = addBytes(destIp, 0, 16, sum)
        // 32-bit UDP payload length, followed by three zero bytes and protocol 17.
        sum += (udp.size ushr 16) + (udp.size and 65535) + 17
        sum = addBytes(udp, 0, udp.size, sum)
        while ((sum ushr 16) != 0L) {
            sum = (sum and 65535L) + (sum ushr 16)
        }
        return sum.inv().toInt() and 65535
    }

    fun parseUdp(packet: ByteArray): Query? {
        if (packet.size < 48 || (u8(packet[0]) ushr 4) != 6 ||
            u8(packet[6]) != 17) return null
        val payloadSize = u16(packet, 4)
        if (payloadSize < 8 || packet.size != 40 + payloadSize ||
            u16(packet, 44) != payloadSize ||
            u16(packet, 46) == 0) return null

        val sourceIp = packet.copyOfRange(8, 24)
        val destinationIp = packet.copyOfRange(24, 40)
        val udp = packet.copyOfRange(40, packet.size)
        if (udpChecksum(sourceIp, destinationIp, udp) != 0) return null
        return Query(
            sourceIp, destinationIp,
            u16(packet, 40), u16(packet, 42),
            packet.copyOfRange(48, packet.size)
        )
    }

    fun buildUdp(
        sourceIp: ByteArray, destinationIp: ByteArray,
        sourcePort: Int, destinationPort: Int, dns: ByteArray
    ): ByteArray? {
        if (sourceIp.size != 16 || destinationIp.size != 16 ||
            dns.size !in 12..4096 ||
            sourcePort !in 1..65535 || destinationPort !in 1..65535) return null
        val udpLength = dns.size + 8
        val packet = ByteArray(40 + udpLength)
        packet[0] = 0x60
        write16(packet, 4, udpLength)
        packet[6] = 17
        packet[7] = 64
        sourceIp.copyInto(packet, 8)
        destinationIp.copyInto(packet, 24)
        write16(packet, 40, sourcePort)
        write16(packet, 42, destinationPort)
        write16(packet, 44, udpLength)
        dns.copyInto(packet, 48)
        val udp = packet.copyOfRange(40, packet.size)
        val checksum = udpChecksum(sourceIp, destinationIp, udp)
        write16(packet, 46, if (checksum == 0) 65535 else checksum)
        return packet
    }
}
