package com.kanaf.alrasby.engine

import android.app.Notification
import android.content.ComponentName
import android.service.quicksettings.TileService
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.content.pm.PackageManager
import android.content.pm.ServiceInfo
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.VpnService
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.database.ContentObserver
import android.provider.Settings
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
import java.util.concurrent.RejectedExecutionException
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
        @Volatile private var initializing = false
        fun isRunning(): Boolean = active
        fun isStarting(): Boolean = initializing
    }

    private var tun: ParcelFileDescriptor? = null
    private val privateDnsObserver = object : ContentObserver(Handler(Looper.getMainLooper())) {
        override fun onChange(selfChange: Boolean) {
            // The user selected Android Private DNS. Do not keep a competing
            // DNS-only VPN route alive when strict/automatic DNS becomes active.
            if (active && !PrivateDnsCompatibility.read(this@KanafDnsVpnService).allowsLocalVpn) {
                stopSelf()
            }
        }
    }

    override fun onCreate() {
        super.onCreate()
        if (Build.VERSION.SDK_INT >= 28) {
            for (name in listOf(
                "private_dns_mode", "private_dns_default_mode", "private_dns_specifier"
            )) {
                runCatching {
                    contentResolver.registerContentObserver(
                        Settings.Global.getUriFor(name), false, privateDnsObserver)
                }
            }
        }
    }
    private var reader: Thread? = null
    private var starting = false
    private var userSession = false
    private val startHandler = Handler(Looper.getMainLooper())

    private fun refreshTile() {
        runCatching {
            TileService.requestListeningState(
                this, ComponentName(this, KanafDnsTileService::class.java)
            )
        }
    }
    private val lock = Any()
    private val threads = ThreadPoolExecutor(
        2, 4, 20, TimeUnit.SECONDS, ArrayBlockingQueue(32),
        // Never run a timed-out resolver call on the only TUN reader thread.
        ThreadPoolExecutor.AbortPolicy()
    )
    // Keep the DNS server paired with the network that advertised it.
    private data class Upstream(val network: Network, val address: InetAddress)
    @Volatile private var cachedDns = emptyList<Upstream>()
    @Volatile private var dnsFetchedAt = 0L

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) {
            stopSelf()
            return START_NOT_STICKY
        }
        // Only the explicit, user-approved action can start the DNS VPN and
        // ever affect global DNS settings. Null or unexpected intents fail closed.
        if (intent?.action != ACTION_START) {
            stopSelf()
            return START_NOT_STICKY
        }
        if (active || starting) return START_NOT_STICKY
        initializing = true
        try {
            val notify = notification()
            if (Build.VERSION.SDK_INT >= 34) {
                startForeground(15041, notify, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
            } else startForeground(15041, notify)
            // Only an explicit user-initiated VPN start can request this handoff.
            check(PrivateDnsToggle.prepare(this)) { "private-dns-permission-required" }
            userSession = true
            starting = true
            establishAfterDnsTransition(0)
        } catch (_: Exception) {
            stopSelf()
        }
        return START_NOT_STICKY
    }

    /**
     * Wait briefly for Android's DNS-over-TLS state to settle after the
     * optional system mode change. Never establish VPN while encrypted DNS is
     * still active; failure rolls back to Auto through onDestroy().
     */
    private fun establishAfterDnsTransition(attempt: Int) {
        if (!starting) return
        try {
            val state = PrivateDnsCompatibility.read(this)
            check(state.mode == PrivateDnsCompatibility.Mode.OFF) {
                "private-dns-was-changed-externally"
            }
            if (!state.allowsLocalVpn) {
                if (attempt < 6) {
                    startHandler.postDelayed({ establishAfterDnsTransition(attempt + 1) }, 400)
                } else stopSelf()
                return
            }
            check(upstreams().isNotEmpty()) { "underlying-dns-unavailable" }
            val builder = Builder().setSession("Kanaf DNS ad filter")
                .setMtu(1500).addAddress(TUN_IP, 32)
                .addDnsServer(DNS_IP).addRoute(DNS_IP, 32).setBlocking(true)
            try { builder.addDisallowedApplication(packageName) }
            catch (_: PackageManager.NameNotFoundException) { /* own app exists */ }
            val descriptor = builder.establish()
                ?: throw IllegalStateException("VPN permission revoked")
            tun = descriptor
            starting = false
            initializing = false
            active = true
            refreshTile()
            reader = Thread({ runLoop(descriptor) }, "kanaf-dns-reader")
                .also { it.start() }
        } catch (_: Exception) {
            stopSelf()
        }
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
            .setSmallIcon(R.drawable.kanaf_status_icon)
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
                    try {
                        threads.execute { handle(packet, output) }
                    } catch (_: RejectedExecutionException) {
                        // Saturated bounded queue: provide a quick local SERVFAIL
                        // instead of stalling every new TUN packet behind DNS I/O.
                        DnsFilterCore.reply(packet, DNS_BYTES) { null }?.let { response ->
                            sendReply(output, response)
                        }
                    }
                }
            }
        } catch (_: Exception) {
            // TUN closed, executor shut down, or worker scheduling rejected.
        } finally {
            stopSelf()
        }
    }

    private fun handle(packet: ByteArray, output: FileOutputStream) {
        val reply = DnsFilterCore.reply(packet, DNS_BYTES, ::forward) ?: return
        sendReply(output, reply)
    }

    private fun sendReply(output: FileOutputStream, reply: ByteArray) {
        synchronized(lock) {
            try { if (active) output.write(reply) }
            catch (_: IOException) { /* interface closed */ }
        }
    }

    private fun forward(request: ByteArray): ByteArray? {
        for (upstream in upstreams().take(4)) {
            try {
                DatagramSocket().use { socket ->
                    // A protected socket avoids recursion; bind it to the exact
                    // underlying network whose DNS server was advertised.
                    if (!protect(socket)) return null
                    upstream.network.bindSocket(socket)
                    socket.soTimeout = 2500
                    socket.connect(InetSocketAddress(upstream.address, 53))
                    socket.send(DatagramPacket(request, request.size))
                    val data = ByteArray(4096)
                    val packet = DatagramPacket(data, data.size)
                    socket.receive(packet)
                    val response = data.copyOf(packet.length)
                    // The central DNS policy verifies the complete DNS
                    // response before anything is sent back into the VPN.
                    return response
                }
            } catch (_: IOException) {
                // Underlying network may have changed; try another resolver.
            } catch (_: SecurityException) {
                // The selected network may have been revoked while binding.
            }
        }
        return null
    }

    /** Underlying network DNS only: never silently send to a custom third party. */
    private fun upstreams(): List<Upstream> {
        val now = SystemClock.elapsedRealtime()
        if (now - dnsFetchedAt < 15_000L) return cachedDns
        val manager = getSystemService(ConnectivityManager::class.java)
        val found = LinkedHashSet<Upstream>()
        for (network in manager.allNetworks) {
            val caps = manager.getNetworkCapabilities(network) ?: continue
            if (caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN) ||
                !caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)) continue
            manager.getLinkProperties(network)?.dnsServers?.forEach { server ->
                if (!server.isLoopbackAddress && server.hostAddress != DNS_IP) {
                    found.add(Upstream(network, server))
                }
            }
        }
        cachedDns = found.toList()
        dnsFetchedAt = now
        return cachedDns
    }

    override fun onRevoke() { stopSelf() }

    override fun onDestroy() {
        runCatching { contentResolver.unregisterContentObserver(privateDnsObserver) }
        starting = false
        initializing = false
        startHandler.removeCallbacksAndMessages(null)
        active = false
        try { tun?.close() } catch (_: IOException) {}
        tun = null
        threads.shutdownNow()
        reader?.interrupt()
        reader = null
        stopForeground(STOP_FOREGROUND_REMOVE)
        if (userSession || PrivateDnsToggle.pending(this)) {
            PrivateDnsToggle.restoreAuto(this)
        }
        userSession = false
        refreshTile()
        super.onDestroy()
    }
}
