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
import com.kanaf.alrasby.BuildConfig
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.IOException
import java.util.concurrent.ArrayBlockingQueue
import java.util.concurrent.RejectedExecutionException
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.TimeUnit

/**
 * Optional local DNS-only VPN. Does not intercept HTTPS, inspect payloads,
 * or collect browsing history. Android allows one VPN at a time.
 * Only IPv4/IPv6 DNS questions sent to Kanaf's dedicated UDP resolver addresses
 * are filtered. Requests are sent over
 * authenticated DNS-over-HTTPS to the selected provider on an underlay network;
 * apps using independent DoH/DoT, IPv6 DNS or first-party ads can bypass it.
 */
class KanafDnsVpnService : VpnService() {
    companion object {
        const val ACTION_START = "com.kanaf.alrasby.DNS_START"
        const val ACTION_STOP = "com.kanaf.alrasby.DNS_STOP"
        const val ACTION_CHANGE_PROVIDER = "com.kanaf.alrasby.DNS_CHANGE_PROVIDER"
        const val EXTRA_PROVIDER = "provider_host"
        private const val CHANNEL_ID = "kanaf_dns_ad_filter_v1"
        private const val TUN_IP = "10.111.222.1"
        private const val DNS_IP = "10.111.222.2"
        private const val TUN_V6_IP = "fd11:beef:cafe::1"
        private const val DNS_V6_IP = "fd11:beef:cafe::2"
        private val DNS_BYTES = byteArrayOf(10, 111, 222.toByte(), 2)
        private val DNS_V6_BYTES = byteArrayOf(
            0xfd.toByte(), 0x11, 0xbe.toByte(), 0xef.toByte(), 0xca.toByte(),
            0xfe.toByte(), 0, 0, 0, 0, 0, 0, 0, 0, 0, 2
        )
        @Volatile private var active = false
        @Volatile private var initializing = false
        fun isRunning(): Boolean = active
        fun isStarting(): Boolean = initializing
        @Volatile private var switching = false
        @Volatile private var switchError: String? = null
        @Volatile private var currentProvider: String? = null
        @Volatile private var sessionCounters: DnsSessionCounters? = null
        fun isSwitching(): Boolean = switching
        fun lastSwitchError(): String? = switchError
        fun activeProvider(): String? = if (active) currentProvider else null
        fun sessionStats(): DnsSessionCounters.Snapshot =
            sessionCounters?.snapshot() ?: DnsSessionCounters.Snapshot(0, 0, 0)
    }

    private var tun: ParcelFileDescriptor? = null
    private val privateDnsObserver = object : ContentObserver(Handler(Looper.getMainLooper())) {
        override fun onChange(selfChange: Boolean) {
            // Strict OS Private DNS must take precedence. Automatic is
            // supported because Kanaf's upstream is encrypted DoH.
            if (active && !PrivateDnsCompatibility.read(this@KanafDnsVpnService).allowsLocalVpn) {
                stopSelf()
            }
        }
    }

    override fun onCreate() {
        super.onCreate()
        DnsDiagnosticPreferences.initialize(this)
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
    @Volatile private var providerAtStart = DnsProviderStore.defaultProvider
    private val counters = DnsSessionCounters()
    private val switchGeneration = java.util.concurrent.atomic.AtomicLong()

    private fun closeTunnel() {
        // Close the actual Android VPN interface immediately, not only the UI toggle.
        active = false
        initializing = false
        starting = false
        switching = false
        switchGeneration.incrementAndGet()
        startHandler.removeCallbacksAndMessages(null)
        val current = tun
        tun = null
        try { current?.close() } catch (_: IOException) {}
        sessionCounters = null
        DnsActivityLog.clear()
        currentProvider = null
        refreshTile()
    }

    private fun changeProvider(host: String?) {
        if (!active || switching || host == null || host !in DnsProviderStore.choices) {
            switchError = "Provider unavailable, connection inactive or change already in progress"
            return
        }
        val requested = host ?: return
        if (requested == providerAtStart) {
            switchError = null
            return
        }
        switching = true
        switchError = null
        val generation = switchGeneration.incrementAndGet()
        Thread({
            val ready = runCatching {
                DnsSecureResolver.isReachable(this, requested)
            }.getOrDefault(false)
            startHandler.post {
                if (generation != switchGeneration.get()) return@post
                if (active && ready &&
                    PrivateDnsCompatibility.read(this).allowsLocalVpn &&
                    DnsProviderStore.choose(this, requested)) {
                    // Existing VPN stays connected: no unfiltered gap or repeated VPN prompt.
                    providerAtStart = requested
                    currentProvider = requested
                    switchError = null
                } else {
                    switchError = "New encrypted DNS provider could not be verified"
                }
                switching = false
            }
        }, "kanaf-doh-provider-check").start()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) {
            closeTunnel()
            stopSelf()
            return START_NOT_STICKY
        }
        if (intent?.action == ACTION_CHANGE_PROVIDER) {
            changeProvider(intent.getStringExtra(EXTRA_PROVIDER))
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
     * An unreachable upstream must fail BEFORE the DNS-only VPN is created.
     * HTTPS probing runs off the main thread. No cleartext DNS fallback.
     */
    private fun establishAfterDnsTransition(attempt: Int) {
        if (!starting) return
        val state = PrivateDnsCompatibility.read(this)
        if (!state.allowsLocalVpn) {
            if (state.mode == PrivateDnsCompatibility.Mode.OFF && attempt < 6) {
                startHandler.postDelayed(
                    { establishAfterDnsTransition(attempt + 1) }, 400)
            } else stopSelf()
            return
        }
        val selected = DnsProviderStore.selected(this)
        Thread({
            val reachable = runCatching {
                DnsSecureResolver.isReachable(this, selected)
            }.getOrDefault(false)
            startHandler.post {
                if (!starting) return@post
                if (!reachable || !PrivateDnsCompatibility.read(this).allowsLocalVpn ||
                    DnsProviderStore.selected(this) != selected) {
                    stopSelf()
                    return@post
                }
                try {
                    val builder = Builder().setSession(
                        if (BuildConfig.KANAF_PLAY_DNS_SECURITY_ONLY)
                            "Kanaf DNS security" else "Kanaf DNS ad filter"
                    )
                        .setMtu(1500).addAddress(TUN_IP, 32)
                        .addDnsServer(DNS_IP).addRoute(DNS_IP, 32)
                        // Route only Kanaf's IPv6 DNS address; never hijack all IPv6 traffic.
                        .addAddress(TUN_V6_IP, 128)
                        .addDnsServer(DNS_V6_IP).addRoute(DNS_V6_IP, 128)
                        .setBlocking(true)
                    try { builder.addDisallowedApplication(packageName) }
                    catch (_: PackageManager.NameNotFoundException) { /* own app */ }
                    val descriptor = builder.establish()
                        ?: throw IllegalStateException("VPN permission revoked")
                    tun = descriptor
                    providerAtStart = selected
                    currentProvider = selected
                    sessionCounters = counters
                    switching = false
                    switchError = null
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
        }, "kanaf-doh-preflight").start()
    }

    private fun notification(): Notification {
        val manager = getSystemService(NotificationManager::class.java)
        manager.createNotificationChannel(NotificationChannel(
            CHANNEL_ID, "Kanaf DNS", NotificationManager.IMPORTANCE_LOW
        ))
        val open = PendingIntent.getActivity(this, 0, Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE)
        val stop = PendingIntent.getService(this, 1,
            Intent(this, KanafDnsVpnService::class.java).setAction(ACTION_STOP),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE)
        return Notification.Builder(this, CHANNEL_ID)
            .setSmallIcon(R.drawable.kanaf_status_icon)
            .setContentTitle(if (BuildConfig.KANAF_PLAY_DNS_SECURITY_ONLY)
                "Kanaf: secure DNS" else "Kanaf: DNS ad filter")
            .setContentText("Encrypted DNS filtering is active. Tap Stop to disconnect.")
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
                        DnsFilterCore.reply(packet, DNS_BYTES, counters, DNS_V6_BYTES) { null }?.let { response ->
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
        val reply = DnsFilterCore.reply(packet, DNS_BYTES, counters, DNS_V6_BYTES, resolver = ::forward) ?: return
        sendReply(output, reply)
    }

    private fun sendReply(output: FileOutputStream, reply: ByteArray) {
        synchronized(lock) {
            try { if (active) output.write(reply) }
            catch (_: IOException) { /* interface closed */ }
        }
    }

    private fun forward(request: ByteArray): ByteArray? =
        DnsSecureResolver.resolve(this, providerAtStart, request)

    override fun onRevoke() { stopSelf() }

    override fun onDestroy() {
        runCatching { contentResolver.unregisterContentObserver(privateDnsObserver) }
        closeTunnel()
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
