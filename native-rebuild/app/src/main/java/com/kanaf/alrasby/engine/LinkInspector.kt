package com.kanaf.alrasby.engine

import java.net.URI
import java.util.Locale

/** Offline URL structure triage. No network requests, browsing or malware reputation checks. */
object LinkInspector {
    const val MAX_TEXT_CHARS = 12_000
    const val MAX_LINKS = 8
    private const val MAX_URL_CHARS = 2_048
    private val urlPattern = Regex("(?i)https?://[^\\s<>\"']+")
    private val ipv4Pattern = Regex("(?:[0-9]{1,3}\\.){3}[0-9]{1,3}")

    enum class Verdict { NOT_VERIFIED, REVIEW, INVALID }
    enum class Signal { UNENCRYPTED_HTTP, USER_INFO, IP_ADDRESS, PUNYCODE, NONSTANDARD_PORT, LONG_URL, INVALID_HOST }
    data class Item(val url: String, val host: String?, val verdict: Verdict, val signals: List<Signal>)
    data class Report(val items: List<Item>, val truncated: Boolean)

    fun inspectText(text: String): Report {
        val source = text.take(MAX_TEXT_CHARS)
        val matches = urlPattern.findAll(source).take(MAX_LINKS + 1).toList()
        return Report(
            items = matches.take(MAX_LINKS).map { inspectUrl(it.value.trimEnd('.', ',', ';', '!', '?', ')')) },
            truncated = text.length > MAX_TEXT_CHARS || matches.size > MAX_LINKS
        )
    }

    private fun inspectUrl(url: String): Item {
        val uri = try { URI(url) } catch (_: Exception) { null }
        val host = uri?.host?.lowercase(Locale.ROOT)
        if (host.isNullOrBlank() || uri.isOpaque ||
            uri.scheme?.lowercase(Locale.ROOT) !in setOf("http", "https")) {
            return Item(url, null, Verdict.INVALID, listOf(Signal.INVALID_HOST))
        }
        val signals = mutableListOf<Signal>()
        if (uri.scheme.equals("http", ignoreCase = true)) signals += Signal.UNENCRYPTED_HTTP
        if (uri.rawUserInfo != null) signals += Signal.USER_INFO
        if (ipv4Pattern.matches(host) || host.contains(':')) signals += Signal.IP_ADDRESS
        if (host.split('.').any { it.startsWith("xn--", ignoreCase = true) }) signals += Signal.PUNYCODE
        val expectedPort = if (uri.scheme.equals("https", ignoreCase = true)) 443 else 80
        if (uri.port >= 0 && uri.port != expectedPort) signals += Signal.NONSTANDARD_PORT
        if (url.length > MAX_URL_CHARS) signals += Signal.LONG_URL
        return Item(url, host, if (signals.isEmpty()) Verdict.NOT_VERIFIED else Verdict.REVIEW, signals)
    }
}
