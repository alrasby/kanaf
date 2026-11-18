package com.kanaf.alrasby.engine

import android.content.Context
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.net.URL
import javax.net.ssl.HttpsURLConnection

/**
 * HTTPS-authenticated DNS wire-format forwarding.
 * No UDP/53 cleartext fallback, no redirects, no browser traffic inspection.
 * Each HTTPS request is bound to an underlying non-VPN Android Network so it
 * cannot loop through the locally advertised Kanaf DNS route.
 */
internal object DnsSecureResolver {
    private const val MAX_RESPONSE = 4096

    fun availableNetworks(context: Context): List<Network> {
        val manager = context.getSystemService(ConnectivityManager::class.java)
        return manager.allNetworks.filter { network ->
            val caps = manager.getNetworkCapabilities(network)
            caps != null && !caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN) &&
                caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
        }
    }

    fun resolve(context: Context, provider: String, request: ByteArray): ByteArray? {
        if (request.size !in 17..MAX_RESPONSE) return null
        val endpoint = DnsProviderStore.endpoint(provider) ?: return null
        for (network in availableNetworks(context).take(3)) {
            try {
                val connection = network.openConnection(URL(endpoint)) as HttpsURLConnection
                connection.connectTimeout = 3000
                connection.readTimeout = 3000
                connection.instanceFollowRedirects = false
                connection.requestMethod = "POST"
                connection.doOutput = true
                connection.useCaches = false
                connection.setRequestProperty("Content-Type", "application/dns-message")
                connection.setRequestProperty("Accept", "application/dns-message")
                connection.setFixedLengthStreamingMode(request.size)
                try {
                    connection.outputStream.use { it.write(request) }
                    if (connection.responseCode != 200) continue
                    if (connection.contentLength > MAX_RESPONSE) continue
                    val out = ByteArrayOutputStream(512)
                    connection.inputStream.use { input ->
                        val buffer = ByteArray(1024)
                        while (out.size() <= MAX_RESPONSE) {
                            val count = input.read(buffer)
                            if (count < 0) break
                            if (count > MAX_RESPONSE - out.size()) break
                            out.write(buffer, 0, count)
                        }
                    }
                    val answer = out.toByteArray()
                    if (DnsPacketCodec.matchesResponse(request, answer)) return answer
                } finally {
                    connection.disconnect()
                }
            } catch (_: IOException) {
                // Try next underlying network; no plaintext downgrade.
            } catch (_: SecurityException) {
                // Network access revoked while connecting.
            } catch (_: ClassCastException) {
                // Refuse a non-HTTPS endpoint.
            }
        }
        return null
    }

    private val probe = byteArrayOf(
        0x57, 0x20, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x07, 'e'.code.toByte(), 'x'.code.toByte(),
        'a'.code.toByte(), 'm'.code.toByte(), 'p'.code.toByte(),
        'l'.code.toByte(), 'e'.code.toByte(), 0x03,
        'c'.code.toByte(), 'o'.code.toByte(), 'm'.code.toByte(),
        0x00, 0x00, 0x01, 0x00, 0x01
    )

    /** Call on background thread before establishing the DNS VPN route. */
    fun isReachable(context: Context, provider: String): Boolean =
        resolve(context, provider, probe) != null
}
