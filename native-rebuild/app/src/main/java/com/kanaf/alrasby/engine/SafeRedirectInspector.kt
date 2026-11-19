package com.kanaf.alrasby.engine

import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.net.URI
import javax.net.ssl.SNIHostName
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory

/** Explicit opt-in HEAD requests. Does not fetch bodies, execute page code,
 * send cookies, follow HTTP downgrades, or connect to private/reserved IPs.
 * Connects to the validated IP with TLS hostname verification, preventing a
 * second DNS lookup (and DNS rebinding) between validation and connection.
 */
object SafeRedirectInspector {
    data class Result(val chain: List<String>, val complete: Boolean, val reason: String)
    data class Response(val status: Int, val location: String?)
    fun permitted(uri: URI): Boolean = uri.scheme.equals("https", true) &&
        uri.userInfo == null && uri.host != null && uri.port in setOf(-1, 443) &&
        uri.toASCIIString().length <= 2048 && LinkDomainReputation.supports(uri.host.lowercase())

    fun publicAddress(address: InetAddress): Boolean {
        if (address.isAnyLocalAddress || address.isLoopbackAddress || address.isLinkLocalAddress ||
            address.isSiteLocalAddress || address.isMulticastAddress) return false
        val bytes = address.address.map { it.toInt() and 255 }
        if (bytes.size == 4) {
            val a = bytes[0]; val b = bytes[1]; val c = bytes[2]
            return !(a == 0 || a == 10 || a == 127 || a >= 224 ||
                a == 100 && b in 64..127 || a == 169 && b == 254 || a == 172 && b in 16..31 ||
                a == 192 && (b == 168 || b == 0 || b == 2) ||
                a == 198 && (b in 18..19 || b == 51 && c == 100) ||
                a == 203 && b == 0 && c == 113)
        }
        // Only global-unicast IPv6; exclude documentation and transition nets.
        return bytes.size == 16 && bytes[0] in 0x20..0x3f &&
            !(bytes[0] == 0x20 && bytes[1] == 0x01 &&
                (bytes[2] < 0x02 || bytes[2] == 0x0d && bytes[3] == 0xb8)) &&
            !(bytes[0] == 0x20 && bytes[1] == 0x02)
    }

    fun inspect(url: String, request: (URI) -> Response = ::head): Result {
        val chain = ArrayList<String>()
        val started = System.nanoTime()
        return try {
            var current = URI(url)
            repeat(5) {
                if (!permitted(current)) return Result(chain, false, "HTTPS public hostname and port 443 required")
                val normalized = current.toASCIIString()
                if (normalized in chain) return Result(chain, false, "Redirect loop")
                if (System.nanoTime() - started > 20_000_000_000L) return Result(chain, false, "Time limit")
                chain += normalized
                val response = request(current)
                if (response.status in setOf(301, 302, 303, 307, 308)) {
                    val location = response.location ?: return Result(chain, false, "Missing redirect location")
                    current = current.resolve(location)
                } else return Result(chain, response.status in 200..299,
                    "HTTP ${response.status}; destination safety unverified")
            }
            Result(chain, false, "Redirect limit")
        } catch (_: Exception) { Result(chain, false, "Unavailable, denied address, invalid URL or TLS/HEAD failure") }
    }

    private fun head(uri: URI): Response {
        require(permitted(uri))
        val addresses = InetAddress.getAllByName(uri.host)
        require(addresses.isNotEmpty() && addresses.all(::publicAddress))
        val plain = Socket()
        try {
            plain.connect(InetSocketAddress(addresses.first(), 443), 3000)
            plain.soTimeout = 3000
            val factory = SSLSocketFactory.getDefault() as SSLSocketFactory
            (factory.createSocket(plain, uri.host, 443, true) as SSLSocket).use { tls ->
                tls.soTimeout = 3000
                tls.sslParameters = tls.sslParameters.apply {
                    endpointIdentificationAlgorithm = "HTTPS"
                    serverNames = listOf(SNIHostName(uri.host))
                }
                tls.startHandshake()
                val ascii = URI(uri.toASCIIString())
                val path = ascii.rawPath.orEmpty().ifBlank { "/" } + (ascii.rawQuery?.let { "?$it" } ?: "")
                require(path.none { it == '\r' || it == '\n' })
                tls.outputStream.write(("HEAD $path HTTP/1.1\r\nHost: ${uri.host}\r\n" +
                    "User-Agent: Kanaf-Link-Inspector/1\r\nConnection: close\r\n\r\n").toByteArray(Charsets.US_ASCII))
                tls.outputStream.flush()
                val header = java.io.ByteArrayOutputStream()
                val headerStarted = System.nanoTime()
                var tail = 0
                while (header.size() < 16_384) {
                    check(System.nanoTime() - headerStarted < 5_000_000_000L && !Thread.currentThread().isInterrupted)
                    val value = tls.inputStream.read()
                    check(value >= 0) { "truncated-http-header" }
                    header.write(value)
                    tail = (tail shl 8) or value
                    if (tail == 0x0d0a0d0a) break
                }
                check(tail == 0x0d0a0d0a) { "http-header-limit" }
                val lines = header.toString("ISO-8859-1").split("\r\n")
                val status = Regex("HTTP/1\\.[01] ([0-9]{3})(?: .*)?").matchEntire(lines.first())
                    ?.groupValues?.get(1)?.toInt() ?: error("invalid-http-status")
                val locations = lines.drop(1).filter { it.startsWith("Location:", true) }
                check(locations.size <= 1)
                return Response(status, locations.firstOrNull()?.substringAfter(':')?.trim())
            }
        } finally { plain.close() }
    }
}
