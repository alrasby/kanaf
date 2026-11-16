package com.kanaf.alrasby.engine

import android.content.Context
import com.kanaf.alrasby.BuildConfig
import java.net.InetAddress
import java.net.URI
import java.security.KeyFactory
import java.security.Signature
import java.security.spec.X509EncodedKeySpec
import java.util.Base64
import kotlin.math.exp
import kotlin.math.ln

/**
 * Experimental URL-lexical phishing score only. Never a file/AV verdict.
 * The string is parsed offline. No DNS lookup, network call or URL opening.
 * Trained model bytes are authenticated with a BUILD-PINNED public key.
 */
class KanafUrlAi private constructor(
    val version: String,
    private val bias: Double,
    private val weights: DoubleArray
) {
    companion object {
        const val FEATURE_COUNT = 12
        private val versionPattern = Regex("[A-Za-z0-9_.-]{1,48}")

        /** Same feature order and transformations as tools/train_url_risk_model.py. */
        internal fun features(raw: String): DoubleArray? {
            if (raw.length !in 5..2048 || raw.any { it.code < 33 || it.code > 126 }) return null
            val uri = try { URI(raw) } catch (_: Exception) { return null }
            val scheme = uri.scheme?.lowercase(java.util.Locale.ROOT) ?: return null
            if (scheme != "http" && scheme != "https") return null
            val host = uri.host?.lowercase(java.util.Locale.ROOT) ?: return null
            if (host.isBlank() || host.length > 253) return null
            // No InetAddress.getByName: it would perform a DNS lookup!
            val ipv4 = Regex("(?:[0-9]{1,3}\\.){3}[0-9]{1,3}").matches(host)
            val ipv6 = host.contains(':')
            val path = uri.rawPath.orEmpty()
            val query = uri.rawQuery.orEmpty()
            fun count(value: Int, cap: Int = 2048) = ln(1.0 + value.coerceIn(0, cap))
            return doubleArrayOf(
                count(raw.length), count(host.length, 253),
                count(raw.count { it in '0'..'9' }),
                count(raw.count { it == '.' }, 200),
                count(raw.count { it == '-' }, 200),
                count(path.length), count(query.length),
                if (scheme == "https") 1.0 else 0.0,
                if (uri.rawUserInfo != null) 1.0 else 0.0,
                if (ipv4 || ipv6) 1.0 else 0.0,
                count((host.split('.').size - 2).coerceAtLeast(0), 30),
                count(raw.count { it == '%' }, 100)
            )
        }

        internal fun parseVerified(bytes: ByteArray, sig: String, publicKeyDer: ByteArray): KanafUrlAi {
            require(bytes.size in 24..4096) { "url-model-size-invalid" }
            val verifier = Signature.getInstance("SHA256withRSA")
            verifier.initVerify(KeyFactory.getInstance("RSA").generatePublic(
                X509EncodedKeySpec(publicKeyDer)))
            verifier.update(bytes)
            require(verifier.verify(Base64.getDecoder().decode(sig.trim()))) {
                "url-model-signature-invalid"
            }
            val str = bytes.toString(Charsets.US_ASCII)
            require(str.toByteArray(Charsets.US_ASCII).contentEquals(bytes) &&
                str.endsWith("\n") && !str.contains("\r")) { "url-model-encoding-invalid" }
            val lines = str.dropLast(1).split('\n')
            require(lines.size == FEATURE_COUNT + 4 && lines[0] == "KanafURLML-1" &&
                lines[1] == "12" && versionPattern.matches(lines[2])) {
                "url-model-format-invalid"
            }
            val numbers = lines.drop(3).map {
                require(Regex("-?[0-9]+(?:\\.[0-9]+)?").matches(it)) {
                    "url-model-number-invalid"
                }
                it.toDouble().also { n -> require(n.isFinite() && n in -100.0..100.0) }
            }
            require(numbers.size == FEATURE_COUNT + 1)
            return KanafUrlAi(lines[2], numbers[0], numbers.drop(1).toDoubleArray())
        }

        fun load(context: Context): KanafUrlAi? {
            val key = BuildConfig.KANAF_URL_MODEL_PUBLIC_KEY_BASE64
            if (key.isBlank()) return null
            return runCatching {
                val model = context.assets.open("url_risk_model.txt").use { it.readBytes() }
                val signature = context.assets.open("url_risk_model.sig")
                    .bufferedReader().use { it.readText() }
                parseVerified(model, signature, Base64.getDecoder().decode(key))
            }.getOrNull()
        }
    }

    /** Probability is a *dataset-relative lexical indicator*, not a safety claim. */
    fun evaluate(url: String): Float? {
        val vector = features(url) ?: return null
        val score = weights.indices.fold(bias) { acc, i -> acc + weights[i] * vector[i] }
        if (!score.isFinite()) return null
        return (1.0 / (1.0 + exp(-score.coerceIn(-40.0, 40.0)))).toFloat()
    }
}
