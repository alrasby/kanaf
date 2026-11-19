package com.kanaf.alrasby.engine

import android.content.Context
import com.kanaf.alrasby.BuildConfig
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.net.URL
import javax.net.ssl.HttpsURLConnection

/**
 * One-tap signed rule database update. Configured ONLY by publisher-built
 * HTTPS URL + pinned PUBLIC signing key; no user URL, insecure fallback, or
 * acceptance of unsigned payloads. Never claims to update native binaries.
 */
class ThreatRuleUpdater {
    data class Availability(val configured: Boolean, val reason: String)

    fun availability(): Availability = when {
        BuildConfig.KANAF_SIGNATURE_PUBLIC_KEY_BASE64.isBlank() ->
            Availability(false, "trusted-production-signing-key-missing")
        BuildConfig.KANAF_SIGNATURE_FEED_URL.isBlank() ->
            Availability(false, "official-rule-feed-url-not-configured")
        else -> Availability(true, "signed-https-feed-available")
    }

    fun update(context: Context): Long {
        if (!availability().configured) throw IOException(availability().reason)
        val url = URL(BuildConfig.KANAF_SIGNATURE_FEED_URL)
        if (url.protocol != "https" || url.userInfo != null) {
            throw IOException("https-feed-required")
        }
        val connection = url.openConnection() as HttpsURLConnection
        connection.connectTimeout = 8000
        connection.readTimeout = 15000
        connection.instanceFollowRedirects = false
        connection.useCaches = false
        try {
            if (connection.responseCode != 200) throw IOException("feed-http-" + connection.responseCode)
            val output = ByteArrayOutputStream()
            val started = System.nanoTime()
            connection.inputStream.use { input ->
                val buffer = ByteArray(16 * 1024)
                val limit = VerifiedSignatureBundle.MAX_DATABASE_BYTES + 16384
                while (true) {
                    if (System.nanoTime() - started > 30_000_000_000L || Thread.currentThread().isInterrupted)
                        throw IOException("feed-download-deadline")
                    val n = input.read(buffer)
                    if (n < 0) break
                    if (n > limit - output.size()) throw IOException("feed-download-too-large")
                    if (n > 0) output.write(buffer, 0, n)
                }
            }
            val parsed = SignedFeedPackage.parse(output.toByteArray().inputStream())
            val key = java.util.Base64.getDecoder()
                .decode(BuildConfig.KANAF_SIGNATURE_PUBLIC_KEY_BASE64)
            check(SignedSignatureUpdate.verify(parsed.manifest, key)) { "untrusted-feed-signature" }
            val actual = java.security.MessageDigest.getInstance("SHA-256").digest(parsed.bytes)
                .joinToString("") { "%02x".format(it.toInt() and 255) }
            check(actual == parsed.manifest.sha256) { "feed-payload-digest-mismatch" }
            val repository = SignatureRepository(context)
            // An identical authenticated feed is a successful up-to-date check.
            // A same-version replacement or an older feed still fails closed.
            val current = runCatching { repository.status() }.getOrNull()
            if (current?.version == parsed.manifest.version && current.sha256 == actual) {
                ProtectionHealth.checkedUpdates(context)
                return current.version
            }
            repository.installVerified(parsed.bytes, parsed.manifest, key)
            ProtectionHealth.checkedUpdates(context)
            return parsed.manifest.version
        } finally { connection.disconnect() }
    }
}
