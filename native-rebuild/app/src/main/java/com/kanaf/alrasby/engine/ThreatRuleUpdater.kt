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
            connection.inputStream.use { input ->
                val buffer = ByteArray(16 * 1024)
                val limit = VerifiedSignatureBundle.MAX_DATABASE_BYTES + 16384
                while (true) {
                    val n = input.read(buffer)
                    if (n < 0) break
                    if (n > limit - output.size()) throw IOException("feed-download-too-large")
                    if (n > 0) output.write(buffer, 0, n)
                }
            }
            val parsed = SignedFeedPackage.parse(output.toByteArray().inputStream())
            val key = java.util.Base64.getDecoder()
                .decode(BuildConfig.KANAF_SIGNATURE_PUBLIC_KEY_BASE64)
            SignatureRepository(context).installVerified(parsed.bytes, parsed.manifest, key)
            return parsed.manifest.version
        } finally { connection.disconnect() }
    }
}
