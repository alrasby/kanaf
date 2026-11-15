package com.kanaf.alrasby.engine

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.content.pm.PackageManager
import android.content.pm.ServiceInfo
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.os.SystemClock
import com.kanaf.alrasby.MainActivity
import com.kanaf.alrasby.R
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.IOException
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.util.concurrent.ArrayBlockingQueue
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.TimeUnit

/**
 * Optional local DNS-only VPN. Does not intercept HTTPS, inspect payloads,
 * or collect browsing history. Android allows one VPN at a time.
 * Blocking applies only to DNS questions that actually traverse this tunnel;
 * private DNS, DoH, first-party ads and IPv6 DNS may bypass it.
 */
class KanafDnsVpnService : VpnService() {
    companion object {
        const val ACTION_START = "com.kanaf.alrasby.DNS_START"
        const val ACTION_STOP = "com.kanaf.alrasby.DNS_STOP"
        private const val CHANNEL_ID = "kanaf_dns_ad_filter_v1"
        private const val TUN_IP = "10.111.222.1"
        private const val DNS_IP = "10.111.222.2"
        private val DNS_BYTES = byteArrayOf(10, 111, 222.toByte(), 2)
        @Volatile private var active = false
        fun isRunning(): Boolean = active
    }

    private var tun: ParcelFileDescriptor? = null
    private var reader: Thread? = null
    private val lock = Any()
    private val threads = ThreadPoolExecutor(
        2, 4, 20, TimeUnit.SECONDS, ArrayBlockingQueue(32),
        ThreadPoolExecutor.CallerRunsPolicy()
    )
    @Volatile private var cachedDns = emptyList<InetAddress>()
    @Volatile private var dnsFetchedAt = 0L

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) {
            stopSelf()
            return START_NOT_STICKY
        }
        if (active) return START_STICKY
        try {
            val notify = notification()
            if (Build.VERSION.SDK_INT >= 34) {
                startForeground(15041, notify, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
            } else startForeground(15041, notify)
            val builder = Builder().setSession("Kanaf DNS ad filter")
                .setMtu(1500).addAddress(TUN_IP, 32)
                .addDnsServer(DNS_IP).addRoute(DNS_IP, 32).setBlocking(true)
            try { builder.addDisallowedApplication(packageName) }
            catch (_: PackageManager.NameNotFoundException) { /* own app always exists */ }
            val descriptor = builder.establish() ?: throw IllegalStateException("VPN permission revoked")
            tun = descriptor
            active = true
            reader = Thread({ runLoop(descriptor) }, "kanaf-dns-reader").also { it.start() }
        } catch (_: Exception) {
            stopSelf()
        }
        return START_NOT_STICKY
    }

    private fun notification(): Notification {
        val manager = getSystemService(NotificationManager::class.java)
        manager.createNotificationChannel(NotificationChannel(
            CHANNEL_ID, "Kanaf DNS filter", NotificationManager.IMPORTANCE_LOW
        ))
        val open = PendingIntent.getActivity(this, 0, Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE)
        val stop = PendingIntent.getService(this, 1,
            Intent(this, KanafDnsVpnService::class.java).setAction(ACTION_STOP),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE)
        return Notification.Builder(this, CHANNEL_ID)
            .setSmallIcon(R.drawable.kanaf_launcher_legacy)
            .setContentTitle("Kanaf: DNS ad filter")
            .setContentText("Limited host blocking is active. Tap Stop to disconnect.")
            .setContentIntent(open).setOngoing(true)
            .addAction(Notification.Action.Builder(null, "Stop", stop).build())
            .build()
    }

    private fun runLoop(descriptor: ParcelFileDescriptor) {
        try {
            val input = FileInputStream(descriptor.fileDescriptor)
            val output = FileOutputStream(descriptor.fileDescriptor)
            val buffer = ByteArray(16384)
            while (active) {
                val count = input.read(buffer)
                if (count < 0) break
                if (count > 0) {
                    val packet = buffer.copyOf(count)
                    threads.execute { handle(packet, output) }
                }
            }
        } catch (_: Exception) {
            // TUN closed, executor shut down, or worker scheduling rejected.
        } finally {
            stopSelf()
        }
    }

    private fun handle(packet: ByteArray, output: FileOutputStream) {
        val query = DnsPacketCodec.parseUdp(packet) ?: return
        if (query.destinationPort != 53 || !query.destinationIp.contentEquals(DNS_BYTES)) return
        val domain = DnsPacketCodec.questionName(query.dns)
        val response = if (domain != null && AdDomainRules.isAdOrTracker(domain)) {
            DnsPacketCodec.nxdomain(query.dns)
        } else forward(query.dns) ?: DnsPacketCodec.servfail(query.dns)
        if (response == null) return
        val reply = DnsPacketCodec.buildUdp(DNS_BYTES, query.sourceIp, 53, query.sourcePort, response)
            ?: return
        synchronized(lock) {
            try { if (active) output.write(reply) }
            catch (_: IOException) { /* interface closed */ }
        }
    }

    private fun forward(request: ByteArray): ByteArray? {
        for (server in upstreams().take(2)) {
            try {
                DatagramSocket().use { socket ->
                    if (!protect(socket)) return null // Prevent recursive VPN routing.
                    socket.soTimeout = 2500
                    socket.connect(InetSocketAddress(server, 53))
                    socket.send(DatagramPacket(request, request.size))
                    val data = ByteArray(4096)
                    val packet = DatagramPacket(data, data.size)
                    socket.receive(packet)
                    val response = data.copyOf(packet.length)
                    if (response.size >= 12 && request.size >= 12 &&
                        response[0] == request[0] && response[1] == request[1] &&
                        (response[2].toInt() and 0x80) != 0) return response
                }
            } catch (_: IOException) {
                // Try the next underlying resolver; never invent an answer.
            }
        }
        return null
    }

    /** Underlying network DNS only: never silently send to a custom third party. */
    private fun upstreams(): List<InetAddress> {
        val now = SystemClock.elapsedRealtime()
        if (now - dnsFetchedAt < 15_000L) return cachedDns
        val manager = getSystemService(ConnectivityManager::class.java)
        val found = LinkedHashSet<InetAddress>()
        for (network in manager.allNetworks) {
            val caps = manager.getNetworkCapabilities(network) ?: continue
            if (caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN) ||
                !caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)) continue
            manager.getLinkProperties(network)?.dnsServers?.forEach { server ->
                if (!server.isLoopbackAddress && server.hostAddress != DNS_IP) found.add(server)
            }
        }
        cachedDns = found.toList()
        dnsFetchedAt = now
        return cachedDns
    }

    override fun onRevoke() { stopSelf() }

    override fun onDestroy() {
        active = false
        try { tun?.close() } catch (_: IOException) {}
        tun = null
        threads.shutdownNow()
        reader?.interrupt()
        reader = null
        stopForeground(STOP_FOREGROUND_REMOVE)
        super.onDestroy()
    }
}
